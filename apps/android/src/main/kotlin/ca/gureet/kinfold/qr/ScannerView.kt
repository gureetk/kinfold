// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
package ca.gureet.kinfold.qr

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.ImageFormat
import android.graphics.Matrix
import android.graphics.RectF
import android.graphics.SurfaceTexture
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.hardware.camera2.params.OutputConfiguration
import android.hardware.camera2.params.SessionConfiguration
import android.media.ImageReader
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import android.util.Size
import android.view.Surface
import android.view.TextureView
import android.view.View
import java.util.concurrent.Executor
import kotlin.math.abs
import kotlin.math.max

/**
 * The app's own QR scanner, on Android's camera API and ZXing: a preview of the back camera, and
 * its frames read on the phone until one holds a QR code, which goes to [onCode] once. Codes come
 * only from here, pointed at a screen or a printout, never from a link or another app (PROTOCOL.md
 * §10.1). Needs the camera permission before it is shown.
 */
@SuppressLint("ViewConstructor")
class ScannerView(context: Context, private val onCode: (String) -> Unit) : TextureView(context), TextureView.SurfaceTextureListener {
    private val cm = context.getSystemService(CameraManager::class.java)
    private var thread: HandlerThread? = null
    private var handler: Handler? = null
    private var camera: CameraDevice? = null
    private var session: CameraCaptureSession? = null
    private var reader: ImageReader? = null
    private var preview: Size? = null

    @Volatile
    private var done = false
    private var lastRead = 0L

    init {
        surfaceTextureListener = this
    }

    override fun onSurfaceTextureAvailable(st: SurfaceTexture, width: Int, height: Int) = open(st)

    override fun onSurfaceTextureSizeChanged(st: SurfaceTexture, width: Int, height: Int) = transform()

    override fun onSurfaceTextureDestroyed(st: SurfaceTexture): Boolean {
        close()
        return true
    }

    override fun onSurfaceTextureUpdated(st: SurfaceTexture) {}

    override fun onWindowVisibilityChanged(visibility: Int) {
        super.onWindowVisibilityChanged(visibility)
        // The camera is for the screen in front of the person only.
        if (visibility != View.VISIBLE) close() else surfaceTexture?.let { if (camera == null) open(it) }
    }

    @SuppressLint("MissingPermission") // checked first
    private fun open(st: SurfaceTexture) {
        if (camera != null || done) return
        if (context.checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) return
        val id = cm.cameraIdList.firstOrNull { cm.getCameraCharacteristics(it).get(CameraCharacteristics.LENS_FACING) == CameraCharacteristics.LENS_FACING_BACK }
            ?: cm.cameraIdList.firstOrNull() ?: return
        val map = cm.getCameraCharacteristics(id).get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP) ?: return
        val shown = closest(map.getOutputSizes(SurfaceTexture::class.java), 1280, 720)
        val read = closest(map.getOutputSizes(ImageFormat.YUV_420_888), 1280, 720)
        preview = shown
        st.setDefaultBufferSize(shown.width, shown.height)
        val t = HandlerThread("kinfold-scanner").also { it.start() }
        val h = Handler(t.looper)
        thread = t
        handler = h
        val r = ImageReader.newInstance(read.width, read.height, ImageFormat.YUV_420_888, 2)
        r.setOnImageAvailableListener({ frame(it) }, h)
        reader = r
        transform()
        cm.openCamera(
            id,
            object : CameraDevice.StateCallback() {
                override fun onOpened(device: CameraDevice) {
                    camera = device
                    configure(device, Surface(st), r.surface, h)
                }

                override fun onDisconnected(device: CameraDevice) {
                    device.close()
                    if (camera == device) camera = null
                }

                override fun onError(device: CameraDevice, error: Int) {
                    device.close()
                    if (camera == device) camera = null
                }
            },
            h,
        )
    }

    private fun configure(device: CameraDevice, shown: Surface, read: Surface, h: Handler) {
        val request = device.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply {
            addTarget(shown)
            addTarget(read)
            set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE)
        }.build()
        val executor = Executor { h.post(it) }
        val config = SessionConfiguration(
            SessionConfiguration.SESSION_REGULAR,
            listOf(OutputConfiguration(shown), OutputConfiguration(read)),
            executor,
            object : CameraCaptureSession.StateCallback() {
                override fun onConfigured(s: CameraCaptureSession) {
                    session = s
                    try {
                        s.setRepeatingRequest(request, null, h)
                    } catch (_: Exception) {
                        // The camera closed meanwhile.
                    }
                }

                override fun onConfigureFailed(s: CameraCaptureSession) {}
            },
        )
        try {
            device.createCaptureSession(config)
        } catch (_: Exception) {
            // The camera closed meanwhile.
        }
    }

    /** One frame: its brightness plane, read at most about seven times a second. */
    private fun frame(r: ImageReader) {
        val image = r.acquireLatestImage() ?: return
        try {
            if (done) return
            val now = SystemClock.elapsedRealtime()
            if (now - lastRead < 140) return
            lastRead = now
            val plane = image.planes[0]
            val buf = plane.buffer
            val bytes = ByteArray(buf.remaining())
            buf.get(bytes)
            val text = Qr.read(bytes, image.width, image.height, plane.rowStride) ?: return
            done = true
            post {
                close()
                onCode(text)
            }
        } finally {
            image.close()
        }
    }

    private fun close() {
        session?.close()
        session = null
        camera?.close()
        camera = null
        reader?.close()
        reader = null
        thread?.quitSafely()
        thread = null
        handler = null
    }

    /** Fills the view with the preview, upright and cropped rather than stretched. */
    private fun transform() {
        val p = preview ?: return
        val w = width.toFloat()
        val h = height.toFloat()
        if (w == 0f || h == 0f) return
        val rotation = display?.rotation ?: Surface.ROTATION_0
        val m = Matrix()
        val cx = w / 2
        val cy = h / 2
        if (rotation == Surface.ROTATION_90 || rotation == Surface.ROTATION_270) {
            val view = RectF(0f, 0f, w, h)
            val buffer = RectF(0f, 0f, p.height.toFloat(), p.width.toFloat())
            buffer.offset(cx - buffer.centerX(), cy - buffer.centerY())
            m.setRectToRect(view, buffer, Matrix.ScaleToFit.FILL)
            val s = max(h / p.height, w / p.width)
            m.postScale(s, s, cx, cy)
            m.postRotate(90f * (rotation - 2), cx, cy)
        } else {
            // Upright already, with the long side vertical; scale so that the shorter fit fills.
            val pw = p.height.toFloat()
            val ph = p.width.toFloat()
            val s = max(w / pw, h / ph)
            m.setScale(pw * s / w, ph * s / h, cx, cy)
            if (rotation == Surface.ROTATION_180) m.postRotate(180f, cx, cy)
        }
        setTransform(m)
    }

    private companion object {
        /** The size nearest [w] by [h] in pixel count, among those with the same shape if there are any. */
        fun closest(sizes: Array<Size>, w: Int, h: Int): Size {
            val shaped = sizes.filter { it.width * h == it.height * w }.ifEmpty { sizes.toList() }
            return shaped.minBy { abs(it.width * it.height - w * h) }
        }
    }
}
