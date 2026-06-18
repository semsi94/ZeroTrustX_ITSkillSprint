import { forwardRef } from "react";

// Neo-Industrial input — flat, dark, crisp border, no neumorphism
const baseStyle = {
  background: "var(--s1)",
  border: "1px solid var(--b1)",
  borderRadius: "var(--r-md)",
  color: "var(--t1)",
  fontSize: 13,
  padding: "7px 11px",
  fontFamily: "var(--font-sans)",
  outline: "none",
  width: "100%",
  boxShadow: "none",
  transition: "border-color var(--t-fast) var(--ease), box-shadow var(--t-fast) var(--ease)",
};

const Input = forwardRef(function Input(
  { className = "", style = {}, onFocus, onBlur, mono = false, ...rest },
  ref,
) {
  return (
    <input
      ref={ref}
      className={className}
      style={{
        ...baseStyle,
        fontFamily: mono ? "var(--font-mono)" : "var(--font-sans)",
        ...style,
      }}
      onFocus={(e) => {
        e.currentTarget.style.borderColor = "var(--b3)";
        e.currentTarget.style.boxShadow = "0 0 0 3px var(--ac-r)";
        onFocus && onFocus(e);
      }}
      onBlur={(e) => {
        e.currentTarget.style.borderColor = "var(--b1)";
        e.currentTarget.style.boxShadow = "none";
        onBlur && onBlur(e);
      }}
      {...rest}
    />
  );
});

export default Input;

export function Select({ children, className = "", style = {}, onFocus, onBlur, ...rest }) {
  return (
    <select
      className={className}
      style={{
        ...baseStyle,
        appearance: "none",
        paddingRight: 28,
        cursor: "pointer",
        ...style,
      }}
      onFocus={(e) => {
        e.currentTarget.style.borderColor = "var(--b3)";
        e.currentTarget.style.boxShadow = "0 0 0 3px var(--ac-r)";
        onFocus && onFocus(e);
      }}
      onBlur={(e) => {
        e.currentTarget.style.borderColor = "var(--b1)";
        e.currentTarget.style.boxShadow = "none";
        onBlur && onBlur(e);
      }}
      {...rest}
    >
      {children}
    </select>
  );
}

export function Textarea({ className = "", style = {}, onFocus, onBlur, mono = false, ...rest }) {
  return (
    <textarea
      className={className}
      style={{
        ...baseStyle,
        fontFamily: mono ? "var(--font-mono)" : "var(--font-sans)",
        minHeight: 96,
        resize: "vertical",
        ...style,
      }}
      onFocus={(e) => {
        e.currentTarget.style.borderColor = "var(--b3)";
        e.currentTarget.style.boxShadow = "0 0 0 3px var(--ac-r)";
        onFocus && onFocus(e);
      }}
      onBlur={(e) => {
        e.currentTarget.style.borderColor = "var(--b1)";
        e.currentTarget.style.boxShadow = "none";
        onBlur && onBlur(e);
      }}
      {...rest}
    />
  );
}
