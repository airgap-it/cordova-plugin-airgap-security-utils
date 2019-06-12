
@objc(SecurityPlugin) class SecurityPlugin : CDVPlugin {
    
    override func pluginInitialize() {
		SecureScreen.activate()
    }
}

