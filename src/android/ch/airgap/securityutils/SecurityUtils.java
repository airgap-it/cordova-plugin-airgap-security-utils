package ch.airgap.securityutils;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.util.Log;
import android.util.Pair;

import java.util.Date;
import java.util.Map;
import java.util.HashMap;
import java.util.function.Consumer;

import android.view.WindowManager;
import android.widget.Toast;
import android.provider.Settings;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;

import ch.papers.securestorage.Storage;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

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
    this.cordova.getActivity().getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
    mKeyguardManager = (KeyguardManager) this.cordova.getActivity().getSystemService(Context.KEYGUARD_SERVICE);
    preferences = this.cordova.getContext().getSharedPreferences("ch.airgap.securityutils", Context.MODE_PRIVATE);
    automaticLocalAuthentication = loadAutoAuthenticationValue();
    actionMap = new HashMap<>();
    actionMap.put("securestorage_initialize", pair -> securestorage_initialize(pair.first, pair.second));
    actionMap.put("securestorage_isDeviceSecure", pair -> securestorage_isDeviceSecure(pair.first, pair.second));
    actionMap.put("securestorage_secureDevice", pair -> securestorage_secureDevice(pair.first, pair.second));
    actionMap.put("securestorage_getItem", pair -> securestorage_getItem(pair.first, pair.second));
    actionMap.put("securestorage_setItem", pair -> securestorage_setItem(pair.first, pair.second));
    actionMap.put("securestorage_removeAll", pair -> securestorage_removeAll(pair.first, pair.second));
    actionMap.put("securestorage_removeItem", pair -> securestorage_removeItem(pair.first, pair.second));
    actionMap.put("securestorage_destroy", pair -> securestorage_destroy(pair.first, pair.second));
    actionMap.put("securestorage_setupParanoiaPassword", pair -> securestorage_setupParanoiaPassword(pair.first, pair.second));
    actionMap.put("localauthentication_authenticate", pair -> localauthentication_authenticate(pair.first, pair.second));
    actionMap.put("localauthentication_setInvalidationTimeout", pair -> localauthentication_setInvalidationTimeout(pair.first, pair.second));
    actionMap.put("localauthentication_invalidate", pair -> localauthentication_invalidate(pair.first, pair.second));
    actionMap.put("localauthentication_toggleAutomaticAuthentication", pair -> localauthentication_toggleAutomaticAuthentication(pair.first, pair.second));
    actionMap.put("localauthentication_setAuthenticationReason", pair -> localauthentication_setAuthenticationReason(pair.first, pair.second));
  }

  private boolean loadAutoAuthenticationValue() {
    return  preferences.getBoolean("autoauth", false);
  }

  private void storeAutoAuthenticationValue(boolean value) {
    SharedPreferences.Editor editor = preferences.edit();
    editor.putBoolean("autoauth", value);
    editor.commit();
  }

  private Storage getStorageForAlias(String alias, boolean isParanoia) {
    return new Storage(this.cordova.getActivity(), alias, isParanoia);
  }

  public boolean execute(String action, JSONArray data, CallbackContext callbackContext) throws JSONException {
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

  private void securestorage_isDeviceSecure(JSONArray data, CallbackContext callbackContext) throws JSONException {
    callbackContext.success(mKeyguardManager.isKeyguardSecure() ? 1 : 0);
  }

  private void securestorage_secureDevice(JSONArray data, CallbackContext callbackContext) throws JSONException {
    Intent intent = new Intent(Settings.ACTION_SECURITY_SETTINGS);
    this.cordova.getActivity().startActivity(intent);
  }

  private void securestorage_getItem(JSONArray data, CallbackContext callbackContext) throws JSONException {
    String alias = data.getString(0);
    boolean isParanoia = data.getBoolean(1);
    String key = data.getString(2);
    this.getStorageForAlias(alias, isParanoia).readString(key, new Function1<String, Unit>() {
      @Override
      public Unit invoke(String s) {
        Log.d(TAG, "read successfully");
        callbackContext.success(s);
        return Unit.INSTANCE;
      }
    }, new Function1<Exception, Unit>() {
      @Override
      public Unit invoke(Exception e) {
        Log.d(TAG, "read unsuccessfully");
        callbackContext.error(e.toString());
        return Unit.INSTANCE;
      }
    }, new Function1<Function0<Unit>, Unit>() {
      @Override
      public Unit invoke(Function0<Unit> function0) {
        authSuccessCallback = function0;
        showAuthenticationScreen();
        return Unit.INSTANCE;
      }
    });
  }

  private void securestorage_setItem(JSONArray data, CallbackContext callbackContext) throws JSONException {
    String alias = data.getString(0);
    boolean isParanoia = data.getBoolean(1);
    String key = data.getString(2);
    String value = data.getString(3);

    this.getStorageForAlias(alias, isParanoia).writeString(key, value, new Function0<Unit>() {
      @Override
      public Unit invoke() {
        Log.d(TAG, "written successfully");
        callbackContext.success();
        return Unit.INSTANCE;
      }
    }, new Function1<Exception, Unit>() {
      @Override
      public Unit invoke(Exception e) {
        Log.d(TAG, "written unsuccessfully");
        callbackContext.error(e.toString());
        return Unit.INSTANCE;
      }
    }, new Function1<Function0<Unit>, Unit>() {
      @Override
      public Unit invoke(Function0<Unit> function0) {
        authSuccessCallback = function0;
        showAuthenticationScreen();
        return Unit.INSTANCE;
      }
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

    this.getStorageForAlias(alias, isParanoia).removeString(key, new Function0<Unit>() {
      @Override
      public Unit invoke() {
        Log.d(TAG, "delete successfully");
        callbackContext.success();
        return Unit.INSTANCE;
      }
    }, new Function1<Exception, Unit>() {
      @Override
      public Unit invoke(Exception e) {
        Log.d(TAG, "delete unsuccessfully");
        callbackContext.error(e.toString());
        return Unit.INSTANCE;
      }
    });
  }

  private void securestorage_destroy(JSONArray data, CallbackContext callbackContext) throws JSONException {
    boolean result = Storage.Companion.destroy(this.cordova.getActivity());
    if (result) {
      callbackContext.success();
    } else {
      callbackContext.error("destroy not successful");
    }
  }

  private void securestorage_setupParanoiaPassword(JSONArray data, CallbackContext callbackContext) throws JSONException {
    String alias = data.getString(0);
    boolean isParanoia = data.getBoolean(1);

    this.getStorageForAlias(alias, isParanoia).setupParanoiaPassword(new Function0<Unit>() {
      @Override
      public Unit invoke() {
        Log.d(TAG, "paranoia successfully setup");
        callbackContext.success();
        return Unit.INSTANCE;
      }
    }, new Function1<Exception, Unit>() {
      @Override
      public Unit invoke(Exception e) {
        Log.d(TAG, "paranoia unsuccessfully");
        callbackContext.error(e.toString());
        return Unit.INSTANCE;
      }
    });
  }

  private void localauthentication_authenticate(JSONArray data, CallbackContext callbackContext) throws JSONException {
      authenticate(result -> {
          if (result) {
              callbackContext.success();
          } else {
              callbackContext.error("Authentication failed");
          }
      });
  }

  private void localauthentication_setInvalidationTimeout(JSONArray data, CallbackContext callbackContext) throws JSONException {
    int timeout = data.optInt(0, 10);
    invalidateAfterSeconds = timeout;
    callbackContext.success();
  }

  private void localauthentication_invalidate(JSONArray data, CallbackContext callbackContext) throws JSONException {
    isAuthenticated = false;
    lastBackgroundDate = null;
    callbackContext.success();
  }

  private void localauthentication_toggleAutomaticAuthentication(JSONArray data, CallbackContext callbackContext) throws JSONException {
    boolean newValue = data.optBoolean(0, false);
    if (newValue != automaticLocalAuthentication) {
      automaticLocalAuthentication = newValue;
      storeAutoAuthenticationValue(newValue);
    }
    callbackContext.success();
  }

  private void localauthentication_setAuthenticationReason(JSONArray data, CallbackContext callbackContext) throws JSONException {
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
    // Create the Confirm Credentials screen. You can customize the title and
    // description. Or
    // we will provide a generic one for you if you leave it null
    Intent intent = mKeyguardManager.createConfirmDeviceCredentialIntent(null, null);
    if (intent != null) {
      this.cordova.setActivityResultCallback(this);
      this.cordova.getActivity().startActivityForResult(intent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS);
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
    isAuthenticated = (lastBackgroundDate.getTime() + (long)(invalidateAfterSeconds * 1000)) >= now.getTime();
    return !isAuthenticated;
  }

  @Override
  public void onResume(boolean multitasking) {
    if (automaticLocalAuthentication) {
        authenticate(result -> {});
    }
  }

  @Override
  public  void onPause(boolean multitasking) {
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
      // Implement your own exception handling logic here..
      // For example:
      System.out.println("handling an exception...");
      // Or ...
      throw new RuntimeException(e);
    }
  }

  void acceptThrows(T elem) throws Exception;

}
