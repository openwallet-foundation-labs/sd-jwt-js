```ts
const presentedSDJwt = await sdjwt.present(encodedSdjwt, presentationKeys);
```

## Parameters

- encodedSdjwt: encoded SD JWT [string]
- presentationKeys: JSON path key to selectively disclosure [Array<string>] (optional)

```ts
{
  data: {
    arr: ['value'];
  }
}

// The JSON Path of value 'value' is 'data.arr.0'
```

## Returns

selectively disclosed encoded SD JWT string.

## presentationKeys

You can check the available presentationKeys by using `presentableKeys` method

```ts
const keys = await sdjwt.presentableKeys();
// return string[]
```
