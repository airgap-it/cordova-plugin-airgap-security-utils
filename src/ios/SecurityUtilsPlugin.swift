import Foundation
import UIKit
import LocalAuthentication

@objc(SecurityUtilsPlugin) class SecurityUtilsPlugin : CDVPlugin {

	private var secureScreen: SecureScreen!
	private var screenCaptureObservers: [String:Observer]!
	private var screenshotObservers: [String:Observer]!

	private var queue: OperationQueue!
    
    override func pluginInitialize() {
		screenCaptureObservers = [String:Observer]()
		screenshotObservers = [String:Observer]()
		secureScreen = SecureScreen()
		secureScreen.startOverlayProtection()

		queue = OperationQueue()
        queue.maxConcurrentOperationCount = 1
        queue.name = "it.airgap.SecureStorageQueue"

		LocalAuthentication.shared.updateAutomaticAuthenticationIfNeeded()
    }

	// MARK: - Secure Screen

	@objc func securescreen_onScreenCaptureStateChanged(_ command: CDVInvokedUrlCommand) {
		let observer = secureScreen.addScreenCaptureObserver { [unowned self] (captured) in
			let result = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: captured)!
			result.keepCallback = true
			self.commandDelegate.send(result, callbackId: command.callbackId)
		}
		screenCaptureObservers[command.callbackId] = observer
		// deliver the first initial state
		let result = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: secureScreen.isCaptured)!
		result.keepCallback = true
		self.commandDelegate.send(result, callbackId: command.callbackId)
	}

	@objc func securescreen_removeScreenCaptureObservers(_ command: CDVInvokedUrlCommand) {
		screenCaptureObservers.removeAll()
		commandDelegate.send(CDVPluginResult(status: CDVCommandStatus_OK), callbackId: command.callbackId)
	}

	@objc func securescreen_onScreenshotTaken(_ command: CDVInvokedUrlCommand) {
		let observer = secureScreen.addScreenshotObserver {
			let result = CDVPluginResult(status: CDVCommandStatus_OK)!
			result.keepCallback = true
			self.commandDelegate.send(result, callbackId: command.callbackId)
		}
		screenshotObservers[command.callbackId] = observer
	}

	@objc func securescreen_removeScreenshotObservers(_ command: CDVInvokedUrlCommand) {
		screenshotObservers.removeAll()
		commandDelegate.send(CDVPluginResult(status: CDVCommandStatus_OK), callbackId: command.callbackId)
	}

	// MARK: - Device Integrity

	@objc func deviceintegrity_assessIntegerity(_ command: CDVInvokedUrlCommand) {
		DeviceIntegrity.assess { assessment in
			let result = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: assessment == .ok)
			self.commandDelegate.send(result, callbackId: command.callbackId)
		}
	}

	// MARK: - Local Authentication

	@objc func localauthentication_authenticate(_ command: CDVInvokedUrlCommand) {
		let localizedReason = command.argument(at: 0) as? String
		LocalAuthentication.shared.authenticate(localizedReason: localizedReason) { result in
			let pluginResult: CDVPluginResult
			switch result {
			case .success(_):
				pluginResult = CDVPluginResult(status: CDVCommandStatus_OK)
			case let .failure(error):
				print(error)
				pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR)
			}
			self.commandDelegate.send(pluginResult, callbackId: command.callbackId)
		}
	}

	@objc func localauthentication_setInvalidationTimeout(_ command: CDVInvokedUrlCommand) {
		let timeout = command.argument(at: 0) as? Int ?? 10
		LocalAuthentication.shared.invalidateAfter = TimeInterval(timeout)
		commandDelegate.send(CDVPluginResult(status: CDVCommandStatus_OK), callbackId: command.callbackId)
	}

	@objc func localauthentication_invalidate(_ command: CDVInvokedUrlCommand) {
		LocalAuthentication.shared.invalidate {
			self.commandDelegate.send(CDVPluginResult(status: CDVCommandStatus_OK), callbackId: command.callbackId)
		}
	}

	@objc func localauthentication_toggleAutomaticAuthentication(_ command: CDVInvokedUrlCommand) {
		let automatic = command.argument(at: 0) as? Bool ?? false
		LocalAuthentication.shared.automatic = automatic
		self.commandDelegate.send(CDVPluginResult(status: CDVCommandStatus_OK), callbackId: command.callbackId)
	}

	@objc func localauthentication_setAuthenticationReason(_ command: CDVInvokedUrlCommand) {
		guard let reason = command.argument(at: 0) as? String, !reason.isEmpty else {
			commandDelegate.send(CDVPluginResult(status: CDVCommandStatus_ERROR), callbackId: command.callbackId)
			return
		}
		LocalAuthentication.shared.localizedAuthenticationReason = reason
		self.commandDelegate.send(CDVPluginResult(status: CDVCommandStatus_OK), callbackId: command.callbackId)
	}

	// MARK: - Secure Storage

	private func storage(forAlias alias: String, isParanoia: Bool) -> SecureStorage {
        let tag = ("it.airgap.keys.biometrics.key-" + alias).data(using: .utf8)!
        return SecureStorage(tag: tag, paranoiaMode: isParanoia)
    }
    
    @objc func securestorage_initialize(_ command: CDVInvokedUrlCommand) {
        queue.addOperation {
            let alias = command.arguments[0] as! String
            let isParanoia = command.arguments[1] as! Bool
			_ = self.storage(forAlias: alias, isParanoia: isParanoia)
            self.commandDelegate.send(
                CDVPluginResult(status: CDVCommandStatus_OK, messageAs: true),
                callbackId: command.callbackId
            )
        }
    }
    
    @objc func securestorage_isDeviceSecure(_ command: CDVInvokedUrlCommand) {
        queue.addOperation {
			let result = LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
			let pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: result)
            
            self.commandDelegate.send(pluginResult, callbackId: command.callbackId)
        }
    }
    
    @objc func securestorage_secureDevice(_ command: CDVInvokedUrlCommand) {
        queue.addOperation {
			guard let settingsUrl = URL(string: UIApplication.openSettingsURLString) else {
                return
            }
    
            if UIApplication.shared.canOpenURL(settingsUrl) {
                UIApplication.shared.open(settingsUrl) { (success) in
                    print("Settings opened: \(success)") // Prints true
                }
            }
            
            self.commandDelegate.send(
                CDVPluginResult(status: CDVCommandStatus_OK, messageAs: true),
                callbackId: command.callbackId
            )
        }
    }
    
    @objc func securestorage_removeAll(_ command: CDVInvokedUrlCommand) {
        queue.addOperation {
            let alias = command.arguments[0] as! String
            let isParanoia = command.arguments[1] as! Bool
            let secureStorage = self.storage(forAlias: alias, isParanoia: isParanoia)
            
            _ = secureStorage.dropSecuredKey()
            
            self.commandDelegate.send(
                CDVPluginResult(status: CDVCommandStatus_OK, messageAs: true),
				callbackId: command.callbackId
            )
        }
    }
    
    @objc func securestorage_removeItem(_ command: CDVInvokedUrlCommand) {
        queue.addOperation {
            let alias = command.arguments[0] as! String
            let isParanoia = command.arguments[1] as! Bool
            let key = command.arguments[2] as! String
            
            let secureStorage = self.storage(forAlias: alias, isParanoia: isParanoia)
			let pluginResult: CDVPluginResult
			do {
				try secureStorage.delete(key: key)
				pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: true)
			} catch {
				pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR)
				print(error)
			}
            
            self.commandDelegate.send(pluginResult, callbackId: command.callbackId)
        }
    }
    
    @objc func securestorage_setItem(_ command: CDVInvokedUrlCommand) {
        queue.addOperation {
            let alias = command.arguments[0] as! String
            let isParanoia = command.arguments[1] as! Bool
            let key = command.arguments[2] as! String
            let value = command.arguments[3] as! String
            
            let secureStorage = self.storage(forAlias: alias, isParanoia: isParanoia)
			secureStorage.store(key: key, value: value) { error in
				let result: CDVPluginResult
				if let error = error {
					print(error)
					result = CDVPluginResult(status: CDVCommandStatus_ERROR)
				} else {
					result = CDVPluginResult(status: CDVCommandStatus_OK)
				}
				self.commandDelegate.send(result, callbackId: command.callbackId)
			}
        }
    }
    
    @objc func securestorage_getItem(_ command: CDVInvokedUrlCommand) {
        queue.addOperation {
            let alias = command.arguments[0] as! String
            let isParanoia = command.arguments[1] as! Bool
            let key = command.arguments[2] as! String

            let secureStorage = self.storage(forAlias: alias, isParanoia: isParanoia)
			secureStorage.retrieve(key: key) { result in
				let pluginResult: CDVPluginResult
				switch result {
				case let .success(value):
					pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: value)
				case let .failure(error):
					print(error)
					pluginResult = CDVPluginResult(status: CDVCommandStatus_ERROR)
				}
				self.commandDelegate.send(pluginResult, callbackId: command.callbackId)
			}
        }
    }
}
