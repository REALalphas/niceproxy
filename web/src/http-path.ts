// Mirrors the public literal-path contract in internal/model/path.go.
export function validHttpPath(value: string): boolean {
  return (
    value === "" ||
    (value.startsWith("/") &&
      new TextEncoder().encode(value).length <= 2048 &&
      !/[\p{White_Space}\p{Cc}*?#[%\\{}]/u.test(value) &&
      !value.includes("//") &&
      !value.split("/").some((segment) => segment === "." || segment === ".."))
  );
}
