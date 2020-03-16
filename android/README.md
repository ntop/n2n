# Building n2n on Android

- Install jdk.
- Generate app keystore by the command `keytool -genkey -alias Hin2n -keystore Hin2n.jks`. And remember these two passwords:

  ```bash
  keytool -genkey -dname "CN=Unknown,O=Unknown,C=Unknown" -keystore Hin2n.jks -keysize 1024 -alias Hin2nalias -validity 14000 -keypass yourpassword -storepass yourpassword
  ```

- Move `Hin2n.jks` to `android/Hin2n/app` directory. We will use this file to sign the application.
- In the file `app/build.gradle` replace `yourpassword` with the password used to generate the keystore.
- Download Android tools from https://developer.android.com/, and unzip it.
- Install Android development environment.
  ```bash
  echo y | ./tools/bin/sdkmanager tools
  echo y | ./tools/bin/sdkmanager platform-tools
  echo y | ./tools/bin/sdkmanager ndk-bundle
  echo y | ./tools/bin/sdkmanager "cmake;3.6.4111459"
  echo y | ./tools/bin/sdkmanager "lldb;3.1"
  ```
- Set environment variables.
  ```bash
  export ANDROID_HOME=YOUE_ANDROID_DEV_HOME
  export ANDROID_NDK_HOME=\$ANDROID_HOME/ndk-bundle
  export HIN2N_KSTOREPWD=YOUR_APP_KEYSTORE_PASSWORD
  export HIN2N_KEYPWD=YOUR_APP_KEY_PASSWORD
  ```
- Compile the app.
  ```bash
  cd android/Hin2n
  ./gradlew assemble
  ```
- You will get the app in `android/Hin2n/app/build/outputs/apk/` directory.
