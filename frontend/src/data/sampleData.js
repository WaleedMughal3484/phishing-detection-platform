export const SAFE_URL_SAMPLE =
  "https://example.com/";


export const SUSPICIOUS_URL_SAMPLE =
  "http://192.0.2.1/secure/account/verify/login";


export const SUSPICIOUS_EMAIL_SAMPLE = {
  sender: "security@example.com",
  subject: "Urgent action required",
  body:
    "Your account will be suspended. " +
    "Verify your account immediately at " +
    "http://192.0.2.1/login",
};