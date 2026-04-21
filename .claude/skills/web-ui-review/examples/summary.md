## Frontend Review: `feature/new-dashboard`

| # | Check | Result | Issue |
|---|-------|--------|-------|
| 1 | Formatting (prettier) | FAIL | `src/components/Card.tsx` needs reformatting |
| 2 | Linting (eslint) | FAIL | `useEffect` missing `userId` in dependency array (`Card.tsx:42`) |
| 3 | TypeScript | FAIL | `props.onSubmit` typed as `any` — use specific callback signature (`Form.tsx:18`) |
| 4 | Accessibility (axe) | FAIL | Button "Submit" has insufficient color contrast (2.8:1, needs 4.5:1) |
| 5 | Responsive (375px) | FAIL | Sidebar overlaps main content at mobile breakpoint |
| 6 | UI/UX Design | FAIL | Card shadow and border-radius inconsistent with design system tokens |
| 7 | Interactions | FAIL | "Cancel" button on modal does not close the dialog |
| 8 | Security | WARN | `dangerouslySetInnerHTML` used in `RichText.tsx:27` — confirm input is sanitized |

Want me to fix any of these?
