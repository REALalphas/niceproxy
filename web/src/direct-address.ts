export function isDirectIP(value: string): boolean {
  if (value.includes(":")) {
    if (!/^[0-9a-fA-F:.]+$/.test(value)) return false;
    try {
      return new URL(`http://[${value}]/`).hostname.startsWith("[");
    } catch {
      return false;
    }
  }
  return (
    /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(value) &&
    value.split(".").every((part) => Number(part) <= 255)
  );
}
export function isDirectTarget(value: string): boolean {
  return (
    isDirectIP(value) ||
    (value.length > 0 &&
      value.length <= 253 &&
      value
        .toLowerCase()
        .split(".")
        .every(
          (label) =>
            label.length <= 63 &&
            /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
        ))
  );
}
