# Button

## Width and label

Loading preserves the button's label and dimensions, blocks the action, and sets aria-busy. Instead of a separate spinner, a dashed SVG outline travels along the button perimeter using the same animation as Loading Profile. The outline updates on text wrapping and width changes via installControlMotion(); corner radii do not stretch on wide buttons. Under reduced motion, the outline remains static. Total duration is defined by the motion.loadingDashes token. Disabled uses the same SVG outline and dashes, without animation; the browser's dashed border is not used on Button.

`width="content"` (default) keeps the content width even inside a stretching Stack. `width="container"` fills the available container width. Both modes are constrained by the container width.

`labelWrap="wrap"` (default) wraps long labels, including unbroken words; the button height grows with its content. `labelWrap="single-line"` keeps a single line with an ellipsis when space is tight; the full content remains accessible to screen readers. `wrap` is preferred for long actions.

```tsx
<Button width="container" labelWrap="wrap" onPress={chooseAction}>
  Continue the journey and explore the unknown road
</Button>
```

In Qwik, `onPress$` is used. These props work with sm/md sizes and existing variants; loading and disabled preserve standard behavior. No application CSS is needed to switch these modes. Container width and wrapping are Alpha's UI extensions, not an extracted Figma variant.

Figma: set 52:340. Names: Default (52:332), Simple (52:407), Blank (52:411), Pressed (52:349), Focused (52:347), Disabled (52:341). In code, variant uses the same names in lowercase. Native :active / :focus-visible / :disabled trigger the corresponding states. Disabled does not execute the action.

Default: extracted Figma context, background #994f4f, height 38/16rem, radius 12/16rem, border 1.5/16rem. Current button text is Manrope 400, minimum 1rem; it replaces Noto Sans Medium from the old mockup. Focused: white border; Pressed: thickened inner border via box-shadow #ddd6, as specified by the user. Simple is transparent with border #9994; Blank is transparent without a border. Disabled: #222222 fill at 33% opacity; muted text, static dashed SVG outline, press blocked. Remaining states were verified in the browser rather than through Figma properties.

All CSS lengths are in rem from a 16px base. Containers use percentages, min/max, and svh; images preserve aspect-ratio. --as-base-size scales the entire system. Numeric width/height in HTML set intrinsic asset proportions; CSS controls rendering size.

Focused and hover are distinct: Focused is a white border. Per user specification, hover switches the border from #9994 to #ddd6 without changing thickness or fill; Blank keeps no border. Hover parameters preserved: delay 0.033s, duration 0.166s.

Border color #9994 was specified by the user; it replaces 10% opacity white.

Text: primary #fff, secondary #ddd (Simple/Blank), disabled #666.

Disabled and Loading Button dashes: shared SVG outline with thickness borderWidth.loading, dash length 3x thickness, and gap 2x thickness. Disabled is static. Both states use identical corner rounding and scaling.
