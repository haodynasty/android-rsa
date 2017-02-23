# android-rsa
rsa encryption and decryption by android

[![License][licence_svg]][licence_url]
[![Download][bintray_svg]][bintray_url]

# Import
add to build.gradle,${latest.version} is [![Download][bintray_svg]][bintray_url]
```
dependencies {
    compile 'com.blakequ.rsa:rsa:${latest.version}'
}
```
maven
```
<dependency>
  <groupId>com.blakequ.rsa</groupId>
  <artifactId>rsa</artifactId>
  <version>${latest.version}</version>
  <type>pom</type>
</dependency>
```


# How to use
you can download example and study how to use

## 1. set key

```
FileEncryptionManager mFileEncryptionManager = FileEncryptionManager.getInstance();
mFileEncryptionManager.generateKey();
//you can invoke getPublickey() and getPrivateKey() to save key to local file
mFileEncryptionManager.setRSAKey(String, String);
```

## 2. encrypt file or data
```
byte[] data = FileUtils.getBytesFromInputStream(getResources().getAssets().open("*.txt"));
byte[] result = mFileEncryptionManager.encryptFileByPublicKey(data, saveEncryFile);
//from file
byte[] result = mFileEncryptionManager.encryptFileByPublicKey(ogirialFile, saveEncryFile);
```

## 3. decrypt file or data
```
byte[] result = mFileEncryptionManager.decryptFileByPrivateKey(encryFile, decryFile);
byte[] result = mFileEncryptionManager.decryptFileByPrivateKey(encryByteData, decryFile);
```

# link
- [BLOG](www.blakequ.com)
- [JAVA_RSA](https://github.com/kobezone/java-android-rsa)


[bintray_svg]: https://api.bintray.com/packages/haodynasty/maven/AndroidRSA/images/download.svg
[bintray_url]: https://bintray.com/haodynasty/maven/AndroidRSA/_latestVersion
[licence_svg]: https://img.shields.io/badge/license-Apache%202-green.svg
[licence_url]: https://www.apache.org/licenses/LICENSE-2.0