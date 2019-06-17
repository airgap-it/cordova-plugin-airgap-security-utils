import Foundation

@objc(SecurityUtilsPlugin) class SecurityUtilsPlugin : CDVPlugin {

	private var secureScreen: SecureScreen!
	private var screenCaptureObservers: [String:SecureScreen.Observer]!
	private var screenshotObservers: [String:SecureScreen.Observer]!
    
    override func pluginInitialize() {
		screenCaptureObservers = [String:SecureScreen.Observer]()
		screenshotObservers = [String:SecureScreen.Observer]()
		secureScreen = SecureScreen()
		secureScreen.startOverlayProtection()
    }

	@objc func onScreenCaptureStateChanged(_ command: CDVInvokedUrlCommand) {
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

	@objc func removeScreenCaptureObservers(_ command: CDVInvokedUrlCommand) {
		screenCaptureObservers.removeAll()
		commandDelegate.send(CDVPluginResult(status: CDVCommandStatus_OK), callbackId: command.callbackId)
	}

	@objc func onScreenshotTaken(_ command: CDVInvokedUrlCommand) {
		let observer = secureScreen.addScreenshotObserver {
			let result = CDVPluginResult(status: CDVCommandStatus_OK)!
			result.keepCallback = true
			self.commandDelegate.send(result, callbackId: command.callbackId)
		}
		screenshotObservers[command.callbackId] = observer
	}

	@objc func removeScreenshotObservers(_ command: CDVInvokedUrlCommand) {
		screenshotObservers.removeAll()
		commandDelegate.send(CDVPluginResult(status: CDVCommandStatus_OK), callbackId: command.callbackId)
	}

	@objc func assessIntegerity(_ command: CDVInvokedUrlCommand) {
		DeviceIntegrity.assess { assessment in
			let result = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: assessment == .ok)
			self.commandDelegate.send(result, callbackId: command.callbackId)
		}
	}
}
