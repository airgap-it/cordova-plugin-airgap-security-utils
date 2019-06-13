var exec = require('cordova/exec');

var PLUGIN_NAME = 'SecurityUtils'

var SecureScreen = {};

SecureScreen.onScreenCaptureStateChanged = function(callback) {
	exec(callback, null, PLUGIN_NAME, 'onScreenCaptureStateChanged', []);
}

SecureScreen.removeScreenCaptureObservers = function() {
	exec(function() {}, null, PLUGIN_NAME, 'removeScreenCaptureObservers', []);	
}

SecureScreen.onScreenshotTaken = function(callback) {
	exec(callback, null, PLUGIN_NAME, 'onScreenshotTaken', []);	
}

SecureScreen.removeScreenshotObservers = function () {
	exec(function() {}, null, PLUGIN_NAME, 'removeScreenshotObservers', []);	
}

exports.SecureScreen = SecureScreen;
