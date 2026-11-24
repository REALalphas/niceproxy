# Icon

`Icon name` принимает тип `IconName`, экспортируемый из `@alpha/core`. В исходном репозитории каталог редактируется в `source/resources/icons.mjs`; установленный пакет уже содержит сгенерированные иконки и типы. React и Qwik используют одинаковые SVG Lucide и API: `name`, необязательные `label`, `weight`.

Для книги, исследования и инвентаря доступны соответственно `book-open`, `compass`, `backpack`. Используй смысловые ресурсы вместо замены на play, disc или wallet.

```tsx
<Icon name="book-open" label="Книга" />
<Icon name="compass" weight="bold" label="Исследование" />
<IconButton icon="backpack" label="Открыть инвентарь" onPress={openInventory} />
```

Без label Icon декоративный и скрыт от скринридера. Для самостоятельного действия используй IconButton с обязательным доступным названием; в Qwik обработчик — onPress$. Regular и bold управляются библиотекой. Приложение не меняет CSS-маски и stroke. Новые ресурсы — расширение типизированного каталога.
