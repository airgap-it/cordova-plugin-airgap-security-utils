# AirGap Security Utils - Cordova Plugin

## Installation
Install the plugin simply using npm:

```
npm install cordova-plugin-airgap-security-utils --save
```

Make sure the plugin is added in your cordova `config.xml` as follows:

```
<plugin name="cordova-plugin-airgap-security-utils" spec="0.3.3" />
```

## iOS

This plugin provides a number of security features.

### Secure Screen

Secure Screen shows an overlay covering the whole screen whenever the app transitions to the inactive state, and removes it before the app becomes active again.
In order for this to work, the app needs to have a storyboard configured for the LaunchScreen.

In addition, this plugin allows you to get notified when a screenshot is taken or the screen is being captured.

### Secure Storage

// TODO

### Local Authentication

// TODO

### Device Integrity

// TODO

## Android

// TODO

## Usage

// TODO

### Secure Screen

To register for screenshot motifications:

```
window.SecurityUtils.SecureScreen.onScreenshotTaken(function() {
	// take action
});
```

To stop receiving screenshot taken events:

```
window.SecurityUtils.SecureScreen.removeScreenshotObservers();
```

To register for screen capture state changes:

```
window.SecurityUtils.SecureScreen.onScreenCaptureStateChanged(function(isCaptured) {
	if (isCaptured) {
		// take action
	} else {
		// take action
	}
});
```

To stop receiving screen capture state changes events:

```
window.SecurityUtils.SecureScreen.removeScreenCaptureObservers();
```

#### Secure Storage

// TODO

#### Local Authentication

// TODO

#### Device Integrity

// TODO
