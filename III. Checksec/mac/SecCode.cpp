// Source: https://github.com/apple-oss-distributions/Security/blob/ef677c3d667a44e1737c1b0245e9ed04d11c51c1/OSX/libsecurity_codesigning/lib/SecCode.cpp#L314C5-L314C5
/*
 * Copyright (c) 2006-2015 Apple Inc. All Rights Reserved.
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

//
// SecCode - API frame for SecCode objects.
//
// Note that some SecCode* functions take SecStaticCodeRef arguments in order to
// accept either static or dynamic code references, operating on the respective
// StaticCode. Those functions are in SecStaticCode.cpp, not here, despite their name.
//
#include "cs.h"
#include "Code.h"
#include "cskernel.h"
#include <security_utilities/cfmunge.h>
#include <security_utilities/logging.h>
#include <xpc/private.h>

using namespace CodeSigning;


//
// CFError user info keys
//
const CFStringRef kSecCFErrorArchitecture =		CFSTR("SecCSArchitecture");
const CFStringRef kSecCFErrorPattern =			CFSTR("SecCSPattern");
const CFStringRef kSecCFErrorResourceSeal =		CFSTR("SecCSResourceSeal");
const CFStringRef kSecCFErrorResourceAdded =		CFSTR("SecCSResourceAdded");
const CFStringRef kSecCFErrorResourceAltered =	CFSTR("SecCSResourceAltered");
const CFStringRef kSecCFErrorResourceMissing =	CFSTR("SecCSResourceMissing");
const CFStringRef kSecCFErrorResourceSideband =	CFSTR("SecCSResourceHasSidebandData");
const CFStringRef kSecCFErrorResourceRecursive =	CFSTR("SecCSResourceRecursive");
const CFStringRef kSecCFErrorInfoPlist =			CFSTR("SecCSInfoPlist");
const CFStringRef kSecCFErrorGuestAttributes =	CFSTR("SecCSGuestAttributes");
const CFStringRef kSecCFErrorRequirementSyntax = CFSTR("SecRequirementSyntax");
const CFStringRef kSecCFErrorPath =				CFSTR("SecComponentPath");


//
// CF-standard type code functions
//
CFTypeID SecCodeGetTypeID(void)
{
	BEGIN_CSAPI
	return gCFObjects().Code.typeID;
    END_CSAPI1(_kCFRuntimeNotATypeID)
}


//
// Get a reference to the calling code.
//
OSStatus SecCodeCopySelf(SecCSFlags flags, SecCodeRef *selfRef)
{
	BEGIN_CSAPI

	checkFlags(flags);
	CFRef<CFMutableDictionaryRef> attributes = makeCFMutableDictionary(1,
		kSecGuestAttributePid, CFTempNumber(getpid()).get());
	CodeSigning::Required(selfRef) = SecCode::autoLocateGuest(attributes, flags)->handle(false);

	END_CSAPI
}


//
// Get the dynamic status of a code.
//
OSStatus SecCodeGetStatus(SecCodeRef codeRef, SecCSFlags flags, SecCodeStatus *status)
{
	BEGIN_CSAPI

	checkFlags(flags);
	CodeSigning::Required(status) = SecCode::required(codeRef)->status();

	END_CSAPI
}


//
// Change the dynamic status of a code
//
OSStatus SecCodeSetStatus(SecCodeRef codeRef, SecCodeStatusOperation operation,
	CFDictionaryRef arguments, SecCSFlags flags)
{
	BEGIN_CSAPI

	checkFlags(flags);
	SecCode::required(codeRef)->status(operation, arguments);

	END_CSAPI
}


//
// Get the StaticCode for an Code
//
OSStatus SecCodeCopyStaticCode(SecCodeRef codeRef, SecCSFlags flags, SecStaticCodeRef *staticCodeRef)
{
	BEGIN_CSAPI

	checkFlags(flags, kSecCSUseAllArchitectures);
	SecPointer<SecStaticCode> staticCode = SecCode::required(codeRef)->staticCode();
	if (flags & kSecCSUseAllArchitectures)
		if (Universal* macho = staticCode->diskRep()->mainExecutableImage())	// Mach-O main executable
			if (macho->narrowed()) {
				// create a new StaticCode comprising the whole fat file
				RefPointer<DiskRep> rep = DiskRep::bestGuess(staticCode->diskRep()->mainExecutablePath());
				staticCode = new SecStaticCode(rep);
			}
	CodeSigning::Required(staticCodeRef) = staticCode ? staticCode->handle() : NULL;

	END_CSAPI
}


//
// Get the host for an Code
//
OSStatus SecCodeCopyHost(SecCodeRef guestRef, SecCSFlags flags, SecCodeRef *hostRef)
{
	BEGIN_CSAPI

	checkFlags(flags);
	SecPointer<SecCode> host = SecCode::required(guestRef)->host();
	CodeSigning::Required(hostRef) = host ? host->handle() : NULL;

	END_CSAPI
}


//
// Find a guest by attribute(s)
//
const CFStringRef kSecGuestAttributeCanonical =		CFSTR("canonical");
const CFStringRef kSecGuestAttributeHash =			CFSTR("codedirectory-hash");
const CFStringRef kSecGuestAttributeMachPort =		CFSTR("mach-port");
const CFStringRef kSecGuestAttributePid =			CFSTR("pid");
const CFStringRef kSecGuestAttributeAudit =			CFSTR("audit");
const CFStringRef kSecGuestAttributeDynamicCode =	CFSTR("dynamicCode");
const CFStringRef kSecGuestAttributeDynamicCodeInfoPlist = CFSTR("dynamicCodeInfoPlist");
const CFStringRef kSecGuestAttributeArchitecture =	CFSTR("architecture");
const CFStringRef kSecGuestAttributeSubarchitecture = CFSTR("subarchitecture");

#if TARGET_OS_OSX
OSStatus SecCodeCopyGuestWithAttributes(SecCodeRef hostRef,
	CFDictionaryRef attributes,	SecCSFlags flags, SecCodeRef *guestRef)
{
	BEGIN_CSAPI

	checkFlags(flags);
	if (hostRef) {
		if (SecCode *guest = SecCode::required(hostRef)->locateGuest(attributes))
			CodeSigning::Required(guestRef) = guest->handle(false);
		else
			return errSecCSNoSuchCode;
	} else
		CodeSigning::Required(guestRef) = SecCode::autoLocateGuest(attributes, flags)->handle(false);

	END_CSAPI
}


//
// Deprecated since 10.6, DO NOT USE. This can be raced.
// Use SecCodeCreateWithAuditToken instead.
//
OSStatus SecCodeCreateWithPID(pid_t pid, SecCSFlags flags, SecCodeRef *processRef)
{
	BEGIN_CSAPI

	checkFlags(flags);
	if (SecCode *guest = KernelCode::active()->locateGuest(CFTemp<CFDictionaryRef>("{%O=%d}", kSecGuestAttributePid, pid)))
		CodeSigning::Required(processRef) = guest->handle(false);
	else
		return errSecCSNoSuchCode;

	END_CSAPI
}

//
// Shorthand for getting the SecCodeRef for a UNIX process
//
OSStatus SecCodeCreateWithAuditToken(const audit_token_t *audit,
									 SecCSFlags flags, SecCodeRef *processRef)
{
	BEGIN_CSAPI
	
	checkFlags(flags);
	CFRef<CFDataRef> auditData = makeCFData(audit, sizeof(audit_token_t));
	if (SecCode *guest = KernelCode::active()->locateGuest(CFTemp<CFDictionaryRef>("{%O=%O}", kSecGuestAttributeAudit, auditData.get()))) {
		CodeSigning::Required(processRef) = guest->handle(false);
	} else {
		return errSecCSNoSuchCode;
	}
	
	END_CSAPI
}

OSStatus SecCodeCreateWithXPCMessage(xpc_object_t message, SecCSFlags flags,
									 SecCodeRef * __nonnull CF_RETURNS_RETAINED target)
{
	BEGIN_CSAPI

	checkFlags(flags);

	if (xpc_get_type(message) != XPC_TYPE_DICTIONARY) {
		return errSecCSInvalidObjectRef;
	}
	
	xpc_connection_t connection = xpc_dictionary_get_remote_connection(message);
	if (connection == NULL) {
		return errSecCSInvalidObjectRef;
	}

	audit_token_t t = {0};
	xpc_connection_get_audit_token(connection, &t);

	return SecCodeCreateWithAuditToken(&t, flags, target);

	END_CSAPI
}

#endif // TARGET_OS_OSX


//
// Check validity of an Code
//
OSStatus SecCodeCheckValidity(SecCodeRef codeRef, SecCSFlags flags,
	SecRequirementRef requirementRef)
{
	return SecCodeCheckValidityWithErrors(codeRef, flags, requirementRef, NULL);
}

OSStatus SecCodeCheckValidityWithErrors(SecCodeRef codeRef, SecCSFlags flags,
	SecRequirementRef requirementRef, CFErrorRef *errors)
{
	BEGIN_CSAPI

	checkFlags(flags,
		  kSecCSConsiderExpiration
		| kSecCSStrictValidate
		| kSecCSStrictValidateStructure
		| kSecCSRestrictSidebandData
		| kSecCSEnforceRevocationChecks
		| kSecCSAllowNetworkAccess
		| kSecCSNoNetworkAccess
	);
	SecPointer<SecCode> code = SecCode::required(codeRef);
	code->checkValidity(flags);
	if (const SecRequirement *req = SecRequirement::optional(requirementRef))
		code->staticCode()->validateRequirement(req->requirement(), errSecCSReqFailed);

	END_CSAPI_ERRORS
}


//
// Collect suitably laundered information about the code signature of a SecStaticCode
// and return it as a CFDictionary.
//
// This API contracts to return a few pieces of information even for unsigned
// code. This means that a SecStaticCodeRef is usable as a basic indentifier
// (i.e. handle) for any code out there.
//
const CFStringRef kSecCodeInfoCertificates =	CFSTR("certificates");
const CFStringRef kSecCodeInfoChangedFiles =	CFSTR("changed-files");
const CFStringRef kSecCodeInfoCMS =				CFSTR("cms");
const CFStringRef kSecCodeInfoDesignatedRequirement = CFSTR("designated-requirement");
const CFStringRef kSecCodeInfoEntitlements =	CFSTR("entitlements");
const CFStringRef kSecCodeInfoEntitlementsDict =	CFSTR("entitlements-dict");
const CFStringRef kSecCodeInfoFlags =			CFSTR("flags");
const CFStringRef kSecCodeInfoFormat =			CFSTR("format");
const CFStringRef kSecCodeInfoDigestAlgorithm =	CFSTR("digest-algorithm");
const CFStringRef kSecCodeInfoDigestAlgorithms = CFSTR("digest-algorithms");
const CFStringRef kSecCodeInfoPlatformIdentifier = CFSTR("platform-identifier");
const CFStringRef kSecCodeInfoIdentifier =		CFSTR("identifier");
const CFStringRef kSecCodeInfoImplicitDesignatedRequirement = CFSTR("implicit-requirement");
const CFStringRef kSecCodeInfoDefaultDesignatedLightweightCodeRequirement = CFSTR("default-designated-lwcr");
const CFStringRef kSecCodeInfoMainExecutable =	CFSTR("main-executable");
const CFStringRef kSecCodeInfoPList =			CFSTR("info-plist");
const CFStringRef kSecCodeInfoRequirements =	CFSTR("requirements");
const CFStringRef kSecCodeInfoRequirementData =	CFSTR("requirement-data");
const CFStringRef kSecCodeInfoSource =			CFSTR("source");
const CFStringRef kSecCodeInfoStatus =			CFSTR("status");
const CFStringRef kSecCodeInfoTeamIdentifier =  CFSTR("teamid");
const CFStringRef kSecCodeInfoTime =			CFSTR("signing-time");
const CFStringRef kSecCodeInfoTimestamp =		CFSTR("signing-timestamp");
const CFStringRef kSecCodeInfoTrust =			CFSTR("trust");
const CFStringRef kSecCodeInfoUnique =			CFSTR("unique");
const CFStringRef kSecCodeInfoCdHashes =        CFSTR("cdhashes");
const CFStringRef kSecCodeInfoCdHashesFull =	CFSTR("cdhashes-full");
const CFStringRef kSecCodeInfoRuntimeVersion = 	CFSTR("runtime-version");
const CFStringRef kSecCodeInfoStapledNotarizationTicket = CFSTR("stapled-ticket");

const CFStringRef kSecCodeInfoCodeDirectory =	CFSTR("CodeDirectory");
const CFStringRef kSecCodeInfoCodeOffset =		CFSTR("CodeOffset");
const CFStringRef kSecCodeInfoDiskRepInfo =     CFSTR("DiskRepInfo");
const CFStringRef kSecCodeInfoEntitlementsDER =	CFSTR("entitlements-DER");
const CFStringRef kSecCodeInfoResourceDirectory = CFSTR("ResourceDirectory");
const CFStringRef kSecCodeInfoNotarizationDate = CFSTR("NotarizationDate");
const CFStringRef kSecCodeInfoCMSDigestHashType = CFSTR("CMSDigestHashType");
const CFStringRef kSecCodeInfoCMSDigest =        CFSTR("CMSDigest");
const CFStringRef kSecCodeInfoSignatureVersion = CFSTR("SignatureVersion");
const CFStringRef kSecCodeInfoLaunchConstraintsSelf = CFSTR("LaunchConstraints-self");
const CFStringRef kSecCodeInfoLaunchConstraintsParent = CFSTR("LaunchConstraints-parent");
const CFStringRef kSecCodeInfoLaunchConstraintsResponsible = CFSTR("LaunchConstraints-responsible");
const CFStringRef kSecCodeInfoLibraryConstraints = CFSTR("LibraryConstraints");

/* DiskInfoRepInfo types */
const CFStringRef kSecCodeInfoDiskRepVersionPlatform =	 	CFSTR("VersionPlatform");
const CFStringRef kSecCodeInfoDiskRepVersionMin =        	CFSTR("VersionMin");
const CFStringRef kSecCodeInfoDiskRepVersionSDK =        	CFSTR("VersionSDK");
const CFStringRef kSecCodeInfoDiskRepNoLibraryValidation = 	CFSTR("NoLibraryValidation");


OSStatus SecCodeCopySigningInformation(SecStaticCodeRef codeRef, SecCSFlags flags,
	CFDictionaryRef *infoRef)
{
	BEGIN_CSAPI

	checkFlags(flags,
		  kSecCSInternalInformation
		| kSecCSSigningInformation
		| kSecCSRequirementInformation
		| kSecCSDynamicInformation
		| kSecCSContentInformation
		| kSecCSSkipResourceDirectory
		| kSecCSCalculateCMSDigest);

	SecPointer<SecStaticCode> code = SecStaticCode::requiredStatic(codeRef);
	CFRef<CFDictionaryRef> info = code->signingInformation(flags);

	if (flags & kSecCSDynamicInformation)
		if (SecPointer<SecCode> dcode = SecStaticCode::optionalDynamic(codeRef))
			info.take(cfmake<CFDictionaryRef>("{+%O,%O=%u}", info.get(), kSecCodeInfoStatus, dcode->status()));

	CodeSigning::Required(infoRef) = info.yield();

	END_CSAPI
}