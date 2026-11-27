// SPDX-License-Identifier: GPL-3.0-or-later WITH LicenseRef-Kinfold-AppStore-Exception
//
// The notification service extension, ca.gureet.kinfold.notifications: what turns an alert push
// (API.md §12, delivery `alert`) into the words the person sees. Apple and the server see only a
// sealed push and a fixed text; the words are made here, on the phone.

import Foundation
import KinfoldCore
import UserNotifications

/**
 * Opens the push with the core, on the app's files, and shows its alert: a silence alert names the
 * person, from the family's records. Anything the extension can't word, or a push that doesn't
 * open, shows the app's fixed text, which is what the notification already holds. iOS gives an
 * extension about 30 seconds; [serviceExtensionTimeWillExpire] shows what there is by then.
 */
final class NotificationService: UNNotificationServiceExtension {
    private var handler: ((UNNotificationContent) -> Void)?
    private var content = UNMutableNotificationContent()
    private var core: IosExtension?

    override func didReceive(_ request: UNNotificationRequest, withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void) {
        handler = contentHandler
        content = (request.content.mutableCopy() as? UNMutableNotificationContent) ?? UNMutableNotificationContent()
        content.title = "Kinfold"
        content.body = Shared.fallbackText
        guard let payload = request.content.userInfo["kinfold"] as? String else { return finish("no_payload") }
        // The core answers on the main thread, where finish runs too.
        DispatchQueue.main.async {
            let core = Shared.extensionCore(route: "alert")
            self.core = core
            core.pushed(payload: payload) { [weak self] outcome in
                guard let self else { return }
                if let title = outcome.title, let text = outcome.text {
                    self.content.title = title
                    self.content.body = text
                }
                self.finish(outcome.kind)
            }
        }
    }

    override func serviceExtensionTimeWillExpire() {
        DispatchQueue.main.async { self.finish("expired") }
    }

    private func finish(_ kind: String) {
        guard let handler else { return }
        self.handler = nil
        core?.log(event: "extension", keys: ["route", "kind", "took_ms", "mem_mb"], values: ["alert", kind, KotlinLong(value: core?.ranMs() ?? -1), KotlinLong(value: Shared.footprintMB())])
        Shared.log.flush()
        handler(content)
    }
}
