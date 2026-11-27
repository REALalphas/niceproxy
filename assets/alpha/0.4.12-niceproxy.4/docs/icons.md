# Icon

`Icon name` accepts the `IconName` type exported from `@alpha/core`. In the source repository, the catalog is edited in `source/resources/icons.mjs`; the installed package already includes generated icons and types. React and Qwik use identical Lucide SVGs and API: `name`, optional `label`, `weight`.

For book, explore, and inventory, `book-open`, `compass`, and `backpack` are available respectively. Use semantic assets instead of substituting play, disc, or wallet.

```tsx
<Icon name="book-open" label="Book" />
<Icon name="compass" weight="bold" label="Explore" />
<IconButton icon="backpack" label="Open inventory" onPress={openInventory} />
```

Without `label`, `Icon` is decorative and hidden from screen readers. For a standalone action, use `IconButton` with a required accessible label; in Qwik, the handler is `onPress$`. Regular and bold are managed by the library. The application does not alter CSS masks or strokes. New assets extend the typed catalog.
