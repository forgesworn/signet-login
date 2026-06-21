/**
 * Phone-class platform detection for the login picker.
 *
 * The picker leads with whichever signer lives on the *other* device: on a phone
 * the Signet app is local ("use this device"), on a desktop it is the phone you
 * scan with ("use your phone"). When we cannot tell, we default to the desktop
 * presentation (other-device first), per mobile-first product guidance.
 */
/** True when the current browser is a phone-class mobile device. */
export declare function isMobile(): boolean;
