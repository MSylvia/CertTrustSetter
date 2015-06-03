# CertTrustSetter
A tool for installing certificates and modifying trust settings in OSX

> Original article and source from: http://support.citrix.com/article/CTX124859

# Summary
This article provides users with instructions for automating the installing and trusting of certificates on Mac OS X. By default, certificates are installed using Apple’s “Keychain Access” application, but this might not be suitable for all users because it requires a certain degree of knowledge and cannot be integrated into an installation process.
Certificates on Mac OS X are stored within Apple’s keychain architecture. The keychain architecture may contain one or more keychains where various security related information - such as passwords and certificates – is stored.  The appropriate level of authentication protects each of these keychains. The keychain that Citrix’ various software products use is the “login” keychain. The current user owns this keychain.
The sample included in this article shows how to add and alter the trust settings of a certificate passed as a file.
It uses calls into Apple’s Certificate, Key and Trust Services API. It is written in “C” and uses Core Foundation calls.

For more information:

> http://developer.apple.com/mac/library/DOCUMENTATION/Security/Conceptual/CertKeyTrustProgGuide
> http://developer.apple.com/mac/library/documentation/CoreFoundation/Reference/CoreFoundation_Collection

# Installing Certificates
To install the certificate, load the data from the certificate into memory.

```
OSStatus result = noErr;
CFDataRef data = NULL;
CFURLRef fileURL = NULL;

fileURL =CFURLCreateFromFileSystemRepresentation( kCFAllocatorDefault,
                                                    (UInt8*)filePath,
                                                     strlen(filePath),
                                                     false );

CFURLCreateDataAndPropertiesFromResource( kCFAllocatorDefault, 
                                            fileURL,
                                            &data, 
                                            NULL, NULL,
                                            &result );
```

After loading the data from the certificate into memory, use `SecCertificateCreateFromData()` to convert it into a certificate and get a `SecCertificateRef`.

```
CSSM_DATA cssmData;
cssmData.Length = CFDataGetLength( data );
cssmData.Data   = (uint8*)CFDataGetBytePtr( data );
result = SecCertificateCreateFromData( &cssmData,
                                        CSSM_CERT_X_509v3,
                                        CSSM_CERT_ENCODING_BER,
                                        certificateRef);
```

Add the `SecCertificateRef` to the keychain with `SecCertificateAddToKeychain()`. If this certificate is already present, an `errSecDuplicateItem` error is returned. You can ignore this error because the returned ref allows changes to the certificate already stored.

```
result = SecCertificateAddToKeychain( *certificateRef, NULL );
if (result == errSecDuplicateItem)
    result = noErr;
```

# Trusting Certificates

Follow the instructions below to trust the certificate you installed.
Use `SecTrustSettingsCopyTrustSettings()` to get the trust settings. This returns a `CFArray` containing each trust setting as a `CFDictionary`. These are immutable and must be converted to `CFMutableArray` and `CFMutableDictionary` before you can make any changes.

## Copying the Trust Policies and Stepping Through Them

Get the trust settings array and copy or create a mutable array

```
result = SecTrustSettingsCopyTrustSettings(     certificateRef,
                                              kSecTrustSettingsDomainUser,
                                              &trustSettingArray );

if (result == noErr)
{
     trustSettingMutArray = CFArrayCreateMutableCopy (NULL, 0, trustSettingArray );
}
else if (result == errSecItemNotFound)
{
     result = noErr;
     trustSettingMutArray = CFArrayCreateMutable (NULL, 0, &kCFTypeArrayCallBacks);
}
```

Step through each trust setting in the array creating a mutable copy of the individual trust dictionary and replacing it in the array.

```
CFIndex trustCounter;
for (trustCounter = 0;
     (result == noErr) && (trustCounter < CFArrayGetCount(trustSettingMutArray));
     trustCounter++)
{
     CFDictionaryRef oneTrustSetting = (CFDictionaryRef)CFArrayGetValueAtIndex (   
                                                                           trustSettingMutArray,
                                                                           trustCounter );
     CFMutableDictionaryRef oneMutTrustSetting= CFDictionaryCreateMutableCopy(NULL,0, oneTrustSetting );

     if (oneMutTrustSetting)
     {
           CFArraySetValueAtIndex ( trustSettingMutArray, trustCounter, oneMutTrustSetting );
```

If the dictionary’s `kSecTrustSettingsPolicy` object matches the policy you are interested in, you have found the correct trust setting. In this sample, it is looking for SSL policy.

In this sample, it is looking for SSL policy.

```
SecPolicyRef policyRef;
if (CFDictionaryGetValueIfPresent ( oneMutTrustSetting,
                                       kSecTrustSettingsPolicy,
                                       (const void**)&policyRef ))
{
     CSSM_OID oid;
     if (SecPolicyGetOID (policyRef, &oid) == noErr)
     {
           if (compareOids( &oid, &CSSMOID_APPLE_TP_SSL) == CSSM_TRUE)
```

After you have found the correct dictionary, you can decide what you need to do with it. There are three possibilities: Remove, change to trusted, or change to not trusted.

## Removing a Policy

To remove a policy, simply remove it from the array. Note that you must decrement the count to ensure all remaining trust settings are checked.

```
CFArrayRemoveValueAtIndex( trustSettingMutArray, trustCounter );
trustCounter--;
```

## Modifying a Policy

The trust status is stored as a CFNumberRef object with the kSecTrustSettingsResult key. If you need to change the setting, use the following procedure:

1. Check the setting by getting the `kSecTrustSettingsResult` object and extracting the trust status with `CFNumberGetValue()`.
2. Compare this value with the value you want to use and if it does not match, create a new `CFNumberRef` with `CFNumberCreate()`, containing the correct trust status.
3. Replace the original key/value pair in the dictionary. In this example we are checking the value is trusted and setting if needed.

```
CFNumberRef numberRef;
if (CFDictionaryGetValueIfPresent ( oneMutTrustSetting,
                                       kSecTrustSettingsResult,
                                       (const void**)&numberRef ))
{
SecTrustSettingsResult trustSettingResult;
     CFNumberGetValue ( numberRef, kCFNumberSInt32Type, &trustSettingResult);

     // Is the trusted value what we want it to be?
if (trustSettingResult != kTrust)
     {
     trustSettingResult = kTrust;
          numberRef = CFNumberCreate(NULL, kCFNumberSInt32Type, &trustSettingResult);
            CFDictionaryReplaceValue( oneMutTrustSetting, kSecTrustSettingsResult, numberRef);
     }
}
```

## Adding a Policy

You add a new policy outside of the search loop described above. You complete this step only if the policy is not found during your search. To add a new policy, use `SecPolicySearchCreate()` and `SecPolicySearchCopyNext()` to create the appropriate `SecPolicyRef`.

```
SecPolicyRef policyRef = NULL;
SecPolicySearchRef policySearchRef = NULL;

result = SecPolicySearchCreate( CSSM_CERT_X_509v3,
                                CSSMOID_APPLE_TP_SSL,
                                NULL,
                                &policySearchRef );
if (result == noErr)
     result = SecPolicySearchCopyNext (  policySearchRef, &policyRef );
```

Create a mutable dictionary and add the `kSecTrustSettingsPolicy` and policy ref object (as found above) to it. Next, create a `CFNumberRef` with the status you want and add it to the dictionary using the `kSecTrustSettingsResult` key.

```
CFMutableDictionaryRef     oneMutTrustSetting = CFDictionaryCreateMutable(
                                                              NULL,
                                                              0,
                                                                 &kCFTypeDictionaryKeyCallBacks,
                                                                 &kCFTypeDictionaryValueCallBack );
CFDictionaryAddValue(oneMutTrustSetting, kSecTrustSettingsPolicy, policyRef);

SecTrustSettingsResult     newTrustStatus = kSecTrustResultConfirm;
CFNumberRef resultType = CFNumberCreate(NULL, kCFNumberSInt32Type, &newTrustStatus);
CFDictionaryAddValue(oneMutTrustSetting, kSecTrustSettingsResult, resultType);
```

Finally append the mutable dictionary to the policies array.

```
CFArrayAppendValue ( trustSettingMutArray, oneMutTrustSetting);
```

## Saving a Policy

After making all your changes, use `SecTrustSettingsSetTrustSettings()` to put the modified trust settings back in place. When the trust settings are back in place, the user is asked to authenticate.

```
result = SecTrustSettingsSetTrustSettings(  certificateRef,
                                             kSecTrustSettingsDomainUser,
                                             trustSettingMutArray );
```

# Improving the Process for Installing and Trusting Certificates

You can use the following two functions to improve the process for installing and trusting certificates. You can also use a helper function to compare oids.

Use `addCertificateWithPath()` to read and install a certificate into the keychain. If the certificate is a duplicate, a `noErr` is returned.
Use the returned `SecCertificateRef` with `trustCertificate()` to set the trust settings. The trust settings are controlled by a linked list of `TrustPolicyAction`.

> Note: that you must link the files against `Security.framework` and `CoreFoundation.framework`.
