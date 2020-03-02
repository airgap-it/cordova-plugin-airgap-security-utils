package ch.airgap.securityutils;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.support.v4.util.Consumer;
import android.util.Log;
import android.util.Pair;

import java.util.Date;
import java.util.Map;
import java.util.HashMap;

import android.view.WindowManager;
import android.widget.Toast;
import android.provider.Settings;

import com.scottyab.rootbeer.RootBeer;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;

import ch.papers.securestorage.Storage;

import it.airgap.vault.BuildConfig;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

public class SecurityUtils extends CordovaPlugin {

  private static final String TAG = "SecureStorage";
  private static final int REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS = 1;

  // auth callbacks
  private Function0<Unit> authSuccessCallback;
  private Function0<Unit> authErrorCallback;

  private KeyguardManager mKeyguardManager;

  private Map<String, ThrowingConsumer<Pair<JSONArray, CallbackContext>>> actionMap;

  private boolean automaticLocalAuthentication = false;
  private Date lastBackgroundDate;
  private int invalidateAfterSeconds = 10;
  private boolean isAuthenticated = false;

  private SharedPreferences preferences;

  public SecurityUtils() {

  }

  @Override
  protected void pluginInitialize() {
    super.pluginInitialize();
    mKeyguardManager = (KeyguardManager) this.cordova.getActivity().getSystemService(Context.KEYGUARD_SERVICE);
    preferences = this.cordova.getContext().getSharedPreferences("ch.airgap.securityutils", Context.MODE_PRIVATE);
    automaticLocalAuthentication = loadAutoAuthenticationValue();
    actionMap = new HashMap<>();
    actionMap.put("securestorage_initialize", pair -> securestorage_initialize(pair.first, pair.second));
    actionMap.put("securestorage_isDeviceSecure", pair -> securestorage_isDeviceSecure(pair.first, pair.second));
    actionMap.put("securestorage_secureDevice", pair -> securestorage_secureDevice(pair.first, pair.second));
    actionMap.put("securestorage_getItem", pair -> securestorage_getItem(pair.first, pair.second));
    actionMap.put("securestorage_setItem", pair -> securestorage_setItem(pair.first, pair.second));
    actionMap.put("secuarestorage_removeAll", pair -> securestorage_removeAll(pair.first, pair.second));
    actionMap.put("securestorage_removeItem", pair -> securestorage_removeItem(pair.first, pair.second));
    actionMap.put("securestorage_destroy", pair -> securestorage_destroy(pair.first, pair.second));
    actionMap.put("securestorage_setupParanoiaPassword",
            pair -> securestorage_setupParanoiaPassword(pair.first, pair.second));
    actionMap.put("securestorage_setupRecoveryPassword",
            pair -> securestorage_setupRecoveryPassword(pair.first, pair.second));
    actionMap.put("localauthentication_authenticate",
            pair -> localauthentication_authenticate(pair.first, pair.second));
    actionMap.put("localauthentication_setInvalidationTimeout",
            pair -> localauthentication_setInvalidationTimeout(pair.first, pair.second));
    actionMap.put("localauthentication_invalidate", pair -> localauthentication_invalidate(pair.first, pair.second));
    actionMap.put("localauthentication_toggleAutomaticAuthentication",
            pair -> localauthentication_toggleAutomaticAuthentication(pair.first, pair.second));
    actionMap.put("localauthentication_setAuthenticationReason",
            pair -> localauthentication_setAuthenticationReason(pair.first, pair.second));
    actionMap.put("deviceintegrity_assess", pair -> deviceintegrity_assess(pair.first, pair.second));
    actionMap.put("securescreen_setWindowSecureFlag", pair -> securescreen_setWindowSecureFlag(pair.first, pair.second));
    actionMap.put("securescreen_clearWindowSecureFlag", pair -> securescreen_clearWindowSecureFlag(pair.first, pair.second));
  }

  public void securescreen_setWindowSecureFlag(JSONArray data, CallbackContext callbackContext) {
    CordovaInterface cordova = this.cordova;
    cordova.getActivity().runOnUiThread(() -> cordova.getActivity().getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE));
    callbackContext.success();
  }

  public void securescreen_clearWindowSecureFlag(JSONArray data, CallbackContext callbackContext) {
    CordovaInterface cordova = this.cordova;
    cordova.getActivity().runOnUiThread(() -> cordova.getActivity().getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE));
    callbackContext.success();
  }

  private boolean loadAutoAuthenticationValue() {
    return preferences.getBoolean("autoauth", false);
  }

  private void storeAutoAuthenticationValue(boolean value) {
    SharedPreferences.Editor editor = preferences.edit();
    editor.putBoolean("autoauth", value);
    editor.apply();
  }

  private Storage getStorageForAlias(String alias, boolean isParanoia) {
    return new Storage(this.cordova.getActivity(), alias, isParanoia);
  }

  public boolean execute(String action, JSONArray data, CallbackContext callbackContext) {
    try {
      ThrowingConsumer<Pair<JSONArray, CallbackContext>> c = actionMap.get(action);
      if (c != null) {
        Pair<JSONArray, CallbackContext> pair = new Pair<>(data, callbackContext);
        c.acceptThrows(pair);
      }
    } catch (Exception exception) {
      callbackContext.error(exception.toString());
      Log.e(TAG, exception.toString(), exception);
    }
    return true;
  }

  private void securestorage_initialize(JSONArray data, CallbackContext callbackContext) throws JSONException {
    String alias = data.getString(0);
    boolean isParanoia = data.getBoolean(1);
    this.getStorageForAlias(alias, isParanoia);
    callbackContext.success();
  }

  private void securestorage_isDeviceSecure(JSONArray data, CallbackContext callbackContext) {
    callbackContext.success(mKeyguardManager.isKeyguardSecure() ? 1 : 0);
  }

  private void securestorage_secureDevice(JSONArray data, CallbackContext callbackContext) {
    Intent intent = new Intent(Settings.ACTION_SECURITY_SETTINGS);
    this.cordova.getActivity().startActivity(intent);
  }

  private void securestorage_getItem(JSONArray data, CallbackContext callbackContext) throws JSONException {
    String alias = data.getString(0);
    boolean isParanoia = data.getBoolean(1);
    String key = data.getString(2);
    if (!assessIntegrity()) {
      callbackContext.error("Invalid state");
      return;
    }
    this.getStorageForAlias(alias, isParanoia).readString(key, item -> {
      Log.d(TAG, "read successfully");
      callbackContext.success(item);
      return Unit.INSTANCE;
    }, error -> {
      Log.d(TAG, "read unsuccessfully");
      callbackContext.error(error.toString());
      return Unit.INSTANCE;
    }, func -> {
      authSuccessCallback = func;
      showAuthenticationScreen();
      return Unit.INSTANCE;
    });
  }

  private void securestorage_setItem(JSONArray data, CallbackContext callbackContext) throws JSONException {
    String alias = data.getString(0);
    boolean isParanoia = data.getBoolean(1);
    String key = data.getString(2);
    String value = data.getString(3);
    if (!assessIntegrity()) {
      callbackContext.error("Invalid state");
      return;
    }
    this.getStorageForAlias(alias, isParanoia).writeString(key, value, () -> {
      Log.d(TAG, "written successfully");
      callbackContext.success();
      return Unit.INSTANCE;
    }, error -> {
      Log.d(TAG, "written unsuccessfully");
      callbackContext.error(error.toString());
      return Unit.INSTANCE;
    }, func -> {
      authSuccessCallback = func;
      showAuthenticationScreen();
      return Unit.INSTANCE;
    });
  }

  private void securestorage_removeAll(JSONArray data, CallbackContext callbackContext) throws JSONException {
    String alias = data.getString(0);
    boolean result = Storage.Companion.removeAll(this.cordova.getActivity(), alias);

    if (result) {
      callbackContext.success();
    } else {
      callbackContext.error("removeAll not successful");
    }
  }

  private void securestorage_removeItem(JSONArray data, CallbackContext callbackContext) throws JSONException {
    String alias = data.getString(0);
    boolean isParanoia = data.getBoolean(1);
    String key = data.getString(2);

    this.getStorageForAlias(alias, isParanoia).removeString(key, () -> {
      Log.d(TAG, "delete successfully");
      callbackContext.success();
      return Unit.INSTANCE;
    }, error -> {
      Log.d(TAG, "delete unsuccessfully");
      callbackContext.error(error.toString());
      return Unit.INSTANCE;
    });
  }

  private void securestorage_destroy(JSONArray data, CallbackContext callbackContext) {
    boolean result = Storage.Companion.destroy(this.cordova.getActivity());
    if (result) {
      callbackContext.success();
    } else {
      callbackContext.error("destroy not successful");
    }
  }

  private void securestorage_setupParanoiaPassword(JSONArray data, CallbackContext callbackContext)
          throws JSONException {
    String alias = data.getString(0);
    boolean isParanoia = data.getBoolean(1);

    this.getStorageForAlias(alias, isParanoia).setupParanoiaPassword(() -> {
      Log.d(TAG, "paranoia successfully setup");
      callbackContext.success();
      return Unit.INSTANCE;
    }, error -> {
      Log.d(TAG, "paranoia unsuccessfully");
      callbackContext.error(error.toString());
      return Unit.INSTANCE;
    });
  }

  private void securestorage_setupRecoveryPassword(JSONArray data, CallbackContext callbackContext) throws JSONException {
    String alias = data.getString(0);
    boolean isParanoia = data.getBoolean(1);
    String key = data.getString(2);
    String value = data.getString(3);
    if (!assessIntegrity()) {
      callbackContext.error("Invalid state");
      return;
    }
    this.getStorageForAlias(alias, isParanoia).writeRecoverableString(key, value, () -> {
      Log.d(TAG,"written recoverable successfully");
      callbackContext.success();
      return Unit.INSTANCE;
    }, error -> {
      Log.d(TAG, "written recoverable unsuccessfully");
      callbackContext.error(error.toString());
      return Unit.INSTANCE;
    }, func -> {
      authSuccessCallback = func;
      showAuthenticationScreen();
      return Unit.INSTANCE;
    });
  }

  private void localauthentication_authenticate(JSONArray data, CallbackContext callbackContext) {
    authenticate(result -> {
      if (result) {
        callbackContext.success();
      } else {
        callbackContext.error("Authentication failed");
      }
    });
  }

  private void localauthentication_setInvalidationTimeout(JSONArray data, CallbackContext callbackContext) {
    int timeout = data.optInt(0, 10);
    invalidateAfterSeconds = timeout;
    callbackContext.success();
  }

  private void localauthentication_invalidate(JSONArray data, CallbackContext callbackContext) {
    isAuthenticated = false;
    lastBackgroundDate = null;
    callbackContext.success();
  }

  private void localauthentication_toggleAutomaticAuthentication(JSONArray data, CallbackContext callbackContext) {
    boolean newValue = data.optBoolean(0, false);
    if (newValue != automaticLocalAuthentication) {
      automaticLocalAuthentication = newValue;
      storeAutoAuthenticationValue(newValue);
    }
    callbackContext.success();
  }

  private void localauthentication_setAuthenticationReason(JSONArray data, CallbackContext callbackContext) {
    callbackContext.success();
  }

  private void authenticate(Consumer<Boolean> consumer) {
    if (!needsAuthentication()) {
      consumer.accept(true);
      return;
    }
    authErrorCallback = () -> {
      this.isAuthenticated = false;
      this.lastBackgroundDate = null;
      consumer.accept(false);
      return Unit.INSTANCE;
    };
    authSuccessCallback = () -> {
      this.isAuthenticated = true;
      this.lastBackgroundDate = null;
      consumer.accept(true);
      return Unit.INSTANCE;
    };
    showAuthenticationScreen();
  }

  private void showAuthenticationScreen() {
    Intent intent = mKeyguardManager.createConfirmDeviceCredentialIntent(null, null);
    if (intent != null) {
      this.cordova.setActivityResultCallback(this);
      this.cordova.getActivity().startActivityForResult(intent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS);
    }
  }

  private void deviceintegrity_assess(JSONArray data, CallbackContext callbackContext) {
    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, assessIntegrity()));
  }

  private final boolean assessIntegrity() {
    Context context = this.cordova.getActivity().getApplicationContext();
    RootBeer rootBeer = new RootBeer(context);
    return !rootBeer.isRootedWithoutBusyBoxCheck() && checkNoDebuggable(context);
  }

  private final boolean checkNoDebuggable(Context context) {
    if (BuildConfig.DEBUG) {
      return true;
    } else {
      return (context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) == 0;
    }
  }

  @Override
  public void onActivityResult(int requestCode, int resultCode, Intent data) {
    super.onActivityResult(requestCode, resultCode, data);
    Log.d(TAG, "onActivityResult");
    if (requestCode == REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS) {
      if (resultCode == Activity.RESULT_OK) {
        Log.d(TAG, "result from callback okay");
        authSuccessCallback.invoke();
        Log.d(TAG, "invoke called");
      } else {
        Toast.makeText(this.cordova.getContext(), "Authentication failed.", Toast.LENGTH_SHORT).show();
        authErrorCallback.invoke();
      }
    }
  }

  private boolean needsAuthentication() {
    if (lastBackgroundDate == null) {
      return !isAuthenticated;
    }
    Date now = new Date();
    isAuthenticated = (lastBackgroundDate.getTime() + (long) (invalidateAfterSeconds * 1000)) >= now.getTime();
    return !isAuthenticated;
  }

  @Override
  public void onResume(boolean multitasking) {
    if (automaticLocalAuthentication) {
      authenticate(result -> {
      });
    }
  }

  @Override
  public void onPause(boolean multitasking) {
    lastBackgroundDate = new Date();
  }

}

@FunctionalInterface
interface ThrowingConsumer<T> extends Consumer<T> {

  @Override
  default void accept(final T elem) {
    try {
      acceptThrows(elem);
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }

  void acceptThrows(T elem) throws Exception;

}