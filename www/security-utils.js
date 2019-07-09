var exec = require('cordova/exec');
var cordova = require('cordova');

var PLUGIN_NAME = 'SecurityUtils';

/*
 ************************
 * Secure Screen		*
 ************************
 */

var SecureScreen = {};
var SecureScreenID = 'securescreen';

SecureScreen.onScreenCaptureStateChanged = function(callback) {
	exec(callback, null, PLUGIN_NAME, SecureScreenID + '_onScreenCaptureStateChanged', []);
}

SecureScreen.removeScreenCaptureObservers = function() {
	exec(function() {}, null, PLUGIN_NAME, SecureScreenID + '_removeScreenCaptureObservers', []);	
}

SecureScreen.onScreenshotTaken = function(callback) {
	exec(callback, null, PLUGIN_NAME, SecureScreenID + '_onScreenshotTaken', []);	
}

SecureScreen.removeScreenshotObservers = function () {
	exec(function() {}, null, PLUGIN_NAME, SecureScreenID + '_removeScreenshotObservers', []);	
}

/*
 ************************
 * Device Integrity		*
 ************************
 */

var DeviceIntegrity = {};
var DeviceIntegrityID = 'deviceintegrity'

DeviceIntegrity.assess = function(callback) {
	exec(callback, null, PLUGIN_NAME, DeviceIntegrityID + '_assessIntegerity', [])
}

/*
 ************************
 * Local Authentication	*
 ************************
 */

 var LocalAuthentication = {};
 var LocalAuthenticationID = "localauthentication";

 LocalAuthentication.authenticate = function(localizedReason, successCallback, errorCallback) {
	 exec(successCallback, errorCallback, PLUGIN_NAME, LocalAuthenticationID + '_authenticate', [localizedReason]);
 }

LocalAuthentication.setInvalidationTimeout = function(timeout, successCallback) {
	exec(successCallback, null, PLUGIN_NAME, LocalAuthenticationID + '_setInvalidationTimeout', [timeout]);
}

LocalAuthentication.invalidate = function(callback) {
	exec(callback, null, PLUGIN_NAME, LocalAuthenticationID + '_invalidate', []);
}

LocalAuthentication.toggleAutomaticAuthentication = function(automatic) {
	exec(null, null, PLUGIN_NAME, LocalAuthenticationID + '_toggleAutomaticAuthentication', [automatic]);
}

LocalAuthentication.setAuthenticationReason = function(reason) {
	exec(null, null, PLUGIN_NAME, LocalAuthenticationID + '_setAuthenticationReason', [reason]);
}

/*
 ************************
 * SECURE STORAGE		*
 ************************
 */

function SecureStorage (alias, isParanoia) {
    this.alias = alias;
    this.isParanoia = isParanoia === true ? true : false;
	this.isInitiated = false;
}
var SecureStorageID = 'securestorage';

SecureStorage.prototype.isDeviceSecure = function (successCallback, errorCallback) {
    exec(successCallback, errorCallback, PLUGIN_NAME, SecureStorageID + "_isDeviceSecure", []);
}

SecureStorage.prototype.secureDevice = function (successCallback, errorCallback) {
    exec(successCallback, errorCallback, PLUGIN_NAME, SecureStorageID + "_secureDevice", []);
	
}
SecureStorage.prototype.isParanoia = function (successCallback, errorCallback) {
    return this.isParanoia
}

SecureStorage.prototype.init = function (successCallback, errorCallback) {
    exec(function(){
        if (this.isParanoia && cordova.platformId === 'android') {
            this.setupParanoiaPassword(function() {
                this.isInitiated = true
                successCallback()
            }.bind(this), errorCallback)
        } else {
            this.isInitiated = true
            successCallback()
        }
    }.bind(this), errorCallback, PLUGIN_NAME, SecureStorageID + "_initialize", [this.alias, this.isParanoia]);
}

SecureStorage.prototype.setItem = function (key, item, successCallback, errorCallback) {
    if (!this.isInitiated) {
        return errorCallback("call initialize() first.")
    }
    exec(successCallback, errorCallback, PLUGIN_NAME, SecureStorageID + "_setItem", [this.alias, this.isParanoia, key, item]);
}

SecureStorage.prototype.getItem = function (key, successCallback, errorCallback) {
    if (!this.isInitiated) {
        return errorCallback("call initialize() first.")
    }
    exec(successCallback, errorCallback, PLUGIN_NAME, SecureStorageID + "_getItem", [this.alias, this.isParanoia, key]);
}

SecureStorage.prototype.removeItem = function (key, successCallback, errorCallback) {
    if (!this.isInitiated) {
        return errorCallback("call initialize() first.")
    }
    exec(successCallback, errorCallback, PLUGIN_NAME, SecureStorageID + "_removeItem", [this.alias, this.isParanoia, key]);
}

SecureStorage.prototype.removeAll = function (successCallback, errorCallback) {
    if (!this.isInitiated) {
        return errorCallback("call initialize() first.")
    }
    exec(successCallback, errorCallback, PLUGIN_NAME, SecureStorageID + "_removeAll", [this.alias, this.isParanoia]);
}

/*
 ************************
 * EXPORTS				*
 ************************
 */

if (cordova.platformId === 'ios') {
	exports.SecureScreen = SecureScreen;
	exports.DeviceIntegrity = DeviceIntegrity;
}
exports.SecureStorage = SecureStorage;
exports.LocalAuthentication = LocalAuthentication;
