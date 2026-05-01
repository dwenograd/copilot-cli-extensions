export function formatZodError(zodError) {
    if (!zodError || !Array.isArray(zodError.issues) || zodError.issues.length === 0) {
        return "validation error";
    }

    return zodError.issues
        .slice(0, 3)
        .map((issue) => {
            const path = issue.path && issue.path.length ? issue.path.join(".") : "(root)";
            return `${path}: ${issue.message}`;
        })
        .join("; ");
}
