//
//  main.c
//  CertTrustSetter
//
//  Created by Matthew Sylvia on 6/3/15.
//  Copyright (c) 2015 Matthew Sylvia. All rights reserved.
//

// Source code from: http://support.citrix.com/article/CTX124859

/*
 *  CertTrustSetter.h
 *  CertTrustTester
 *
 *  Created by Don Swatman on 24-Feb-2010.
 *  Copyright 2010 Citrix Systems, Inc. All Rights Reserved.
 *
 *  This sample code is provided to you “AS IS” with no representations,
 *  warranties or conditions of any kind.
 *
 *  You may use, modify and distribute it at your own risk.
 *  CITRIX DISCLAIMS ALL WARRANTIES WHATSOEVER, EXPRESS, IMPLIED, WRITTEN,
 *  ORAL OR STATUTORY,  INCLUDING WITHOUT LIMITATION WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND
 *  NONINFRINGEMENT.
 *
 *  Without limiting the generality of the foregoing, you acknowledge and
 *  agree that
 * (a) the sample code may exhibit errors, design flaws or other problems,
 *     possibly resulting in loss of data or damage to property;
 * (b) it may not be possible to make the sample code fully functional;
 *  and
 * (c) Citrix may, without notice or liability to you, cease to make
 *     available the current version and/or any future versions of the
 *     sample code.
 *
 *  In no event should the code be used to support of ultra-hazardous
 *  activities, including but not limited to life support or blasting
 *  activities.
 *  NEITHER CITRIX NOR ITS AFFILIATES OR AGENTS WILL BE LIABLE, UNDER
 *  BREACH OF CONTRACT OR ANY OTHER THEORY OF LIABILITY, FOR ANY DAMAGES
 *  WHATSOEVER ARISING FROM USE OF THE SAMPLE CODE, INCLUDING WITHOUT
 *  LIMITATION DIRECT, SPECIAL, INCIDENTAL, PUNITIVE, CONSEQUENTIAL OR
 *  OTHER DAMAGES, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
 *
 *  Although the copyright in the code belongs to Citrix, any distribution
 *  of the code should include only your own standard copyright attribution,
 *  and not that of Citrix.
 *  You agree to indemnify and defend Citrix against any and all claims
 *  arising from your use, modification or distribution of the code.
 */


#include <CoreFoundation/CoreFoundation.h>

#include "CertTrustSetter.h"

void displayHelp();

// --------------------------------------------------------
// main
// --------------------------------------------------------

int main (int argc, const char * argv[])
{
    TrustPolicyAction*    onePolicyAction  = NULL;
    TrustPolicyAction*    policyActions    = NULL;
    
    printf("\n");
    printf("CertTrustSetter\n");
    printf("------------------\n");
    printf("\n");
    
    // -------- Parse the parameters ---------
    int argIndex = 1;
    if (   (argc <= 1)
        || (*argv[argIndex] == '?'))
    {
        displayHelp();
        return 0;
    }
    
    int paramCount = 1;
    while (   (argIndex < argc)
           && (*argv[argIndex] == '-'))
    {
        const char cmd = argv[argIndex][1];
        if (cmd == '?')
        {
            displayHelp();
            return 0;
        }
        else if (   (cmd == 't')
                 || (cmd == 'd')
                 || (cmd == 'r'))
        {
            argIndex++;
            if (argIndex >= argc)
            {
                printf("\tMissing Parameter (%i) after \"%s\"\n",
                       paramCount, argv[argIndex-1] );
                printf("\tUse \"-?\" for help\n");
                return -1;
            }
            
            
            const CSSM_OID* policy = NULL;
            if (strcmp( argv[argIndex], "SSL") == 0)
                policy = &CSSMOID_APPLE_TP_SSL;
            else if (strcmp( argv[argIndex], "SMIME") == 0)
                policy = &CSSMOID_APPLE_TP_SMIME;
            else if (strcmp( argv[argIndex], "EAP") == 0)
                policy = &CSSMOID_APPLE_TP_EAP;
            else if (strcmp( argv[argIndex], "IPsec") == 0)
                policy = &CSSMOID_APPLE_TP_IP_SEC;
            else if (strcmp( argv[argIndex], "iChat") == 0)
                policy = &CSSMOID_APPLE_TP_ICHAT;
            else if (strcmp( argv[argIndex], "KbosC") == 0)
                policy = &CSSMOID_APPLE_TP_PKINIT_CLIENT;
            else if (strcmp( argv[argIndex], "KbosS") == 0)
                policy = &CSSMOID_APPLE_TP_PKINIT_SERVER;
            else if (strcmp( argv[argIndex], "Code") == 0)
                policy = &CSSMOID_APPLE_TP_CODE_SIGNING;
            else if (strcmp( argv[argIndex], "X509") == 0)
                policy = &CSSMOID_APPLE_X509_BASIC;
            else
            {
                printf("\tBad Parameter (%i)  \"%s %s\"\n", paramCount,
                       argv[argIndex-1],
                       argv[argIndex] );
                printf("\tUse \"-?\" for help\n");
                return -1;
            }
            
            onePolicyAction = (TrustPolicyAction*)malloc( sizeof(TrustPolicyAction));
            onePolicyAction->policy     = policy;
            onePolicyAction->handled    = false;
            onePolicyAction->nextAction = policyActions;
            policyActions               = onePolicyAction;
            
            
            if (cmd == 't')
                onePolicyAction->action = kTrust;
            else if (cmd == 'd')
                onePolicyAction->action = kDeny;
            else
                onePolicyAction->action = kRemove;
            
        }
        else
        {
            printf("\tBad Parameter (%i)  \"%s\"\n", paramCount, argv[argIndex] );
            printf("\tUse \"-?\" for help\n");
            return -1;
        }
        
        paramCount++;
        argIndex ++;
    }
    
    if (argIndex >= argc)
    {
        printf("\tNo files\n", paramCount, argv[argIndex-1] );
        printf("\tUse \"-?\" for help\n");
        return -1;
    }
    
    
    // -------- Step through the certificates -----------
    OSStatus result = noErr;
    for (; (argIndex < argc) && (result == noErr); argIndex++)
    {
        SecCertificateRef certRef = NULL;
        printf("File -  %s\n", argv[argIndex]);
        
        // Add the certificate
        result = addCertificateWithPath(argv[argIndex], &certRef);
        if (result != noErr)
        {
            printf("\tFailed to Add\n");
        }
        else
        {
            printf("\tSuccessfully Added\n");
            
            // Trust the certificate
            if (policyActions )
            {
                result = trustCertificate( certRef, policyActions );
                if (result != noErr)
                    printf("\tFailed to set trust values\n");
                else
                    printf("\tSuccessfully set trust values\n");
            }
        }
        
        
        if (certRef)
            CFRelease(certRef);
    }
    // Clean up
    onePolicyAction = policyActions;
    while (onePolicyAction)
    {
        TrustPolicyAction* actionToDelete = onePolicyAction;
        onePolicyAction = onePolicyAction->nextAction;
        free(actionToDelete);
    }
    
    
    return result;
}

// --------------------------------------------------------
// displayHelp()
// --------------------------------------------------------
void displayHelp()
{
    printf("NAME\n");
    printf("    CertTrustSetter -- load or set the trust policies of a certificate\n");
    printf("\n");
    printf("SYNOPSIS\n");
    printf("    CertTrustSetter [-?] [-t policy]... [-d policy]... "
           "[-r policy]... file ...\n");
           printf("\n");
           printf("DESCRIPTION\n");
           printf("    The CertTrustSetter utility can add and trust one or "
                  "more certificate files. If the certificate is already "
                  "loaded then it will adjust the trust policies.\n");
                  printf("    There must be at least one file. "
                         "If there are no policies, then the certificate will only be added. "
                         "There can be multiple policy settings.\n");
                         printf("    \n");
                         printf("    -?          Help (does no further processing)\n");
                         printf("    -t policy   Trust policy (See below)\n");
                         printf("    -d policy   Deny policy (See below)\n");
                         printf("    -r policy   Remove policy (See below)\n");
                         printf("    file(s)     One or more files. Must last parameters.\n");
                         printf(" \n");
                         printf("    policy\n");
                         printf("        SSL     Secure Socket Layer\n");
                         printf("        SMIME   Secure Mail (S/MIME )\n");
                         printf("        EAP     Extensible Authentication\n");
                         printf("        IPsec   IP Security\n");
                         printf("        iChat   iChat Security\n");
                         printf("        KbosC   Kerberos Client\n");
                         printf("        KbosS   Kerberos Server\n");
                         printf("        Code    Code Signing\n");
                         printf("        X509    X.509 Basic Policy\n");
                         printf(" \n");
                         printf("EXAMPLES\n");
                         printf("    CertTrustSetter Certificate.cer\n");
                         printf("    CertTrustSetter -t SSL -t X509 \"Certificate.cer\"\n");
                         printf("    CertTrustSetter -t SSL -d iChat Certificate.cer\n");
                         printf("    CertTrustSetter -t SSL -r iChat Certificate.cer\n");
}