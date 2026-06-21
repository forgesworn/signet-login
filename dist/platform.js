/**
 * Phone-class platform detection for the login picker.
 *
 * The picker leads with whichever signer lives on the *other* device: on a phone
 * the Signet app is local ("use this device"), on a desktop it is the phone you
 * scan with ("use your phone"). When we cannot tell, we default to the desktop
 * presentation (other-device first), per mobile-first product guidance.
 */
/** True when the current browser is a phone-class mobile device. */
export function isMobile() {
    if (typeof navigator === 'undefined')
        return false;
    // Client Hints are authoritative where supported (Chromium). Use them first.
    const uaData = navigator.userAgentData;
    if (uaData && typeof uaData.mobile === 'boolean')
        return uaData.mobile;
    // Phone-class only. Android tablets omit the "Mobile" token, and iPadOS reports
    // as desktop Safari — both are treated as desktop on purpose, since their larger
    // screens suit the other-device-first layout.
    const ua = navigator.userAgent || '';
    return /android.+mobile|iphone|ipod|iemobile|blackberry|bb10|opera mini|windows phone|webos/i.test(ua);
}
