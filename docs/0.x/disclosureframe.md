To issue claims into a valid SD-JWT we use Disclosure Frame to define which properties should be selectively diclosable.
We use two special property that you can't use in your claim.

```ts
{
  _sd: string[],
  _sd_decoy: number,
}
```

- `_sd`: the property name that can be selectively diclosable.
- `_sd_decoy`: an optional property that defines the number of decoy digests to add.

## Examples

- Object

```ts
const claims = {
  firstname: 'John',
  lastname: 'Doe'
}
const diclosureFrame = {
  _sd: ['firstname'] // set firstname as selectively discloseable
}

const result = {
  _sd: ['JoQEib3CnAVoYzYLSk6E9I1ZPR4HbMzHt8qL671Si4o']
  lastname: 'Doe',
}
```

- Array

```ts
const claims = {
  data: ['A', 'B'],
};

const disclosureFrame = {
  data: {
    _sd: [0, 1], // index of 'data' Array
  },
};

const result = {
  data: [
    { '...': 'zrdMe3fQZCTNK4eb-5tlPcXP9Ea17fcD3FuGPx06C04' },
    { '...': 'dVM4-VFC0txjO1UnVZ7DALN0thT3UXgXI8krWFL5Nj8' },
  ],
};
```

- Nested Object

```ts
const claims = {
  color: {
    title: '#232323',
    footer: '#121212',
    button: '#fefefe',
  },
};

const disclosureFrame = {
  color: {
    // set color.title and color.footer as selectively discloseable
    _sd: ['title', 'footer'],
  },
};

const result = {
  color: {
    _sd: [
      '02d7bUYevjfAzJ0Gr42ymHy66ezQVL7huNGBO68xSfs',
      'ai7P4vgPZ-Jk1QwL55BLQqtN2gwWy31-pi2VGWiIggs',
    ],
    button: '#fefefe',
  },
};
```

- Array in array

```ts
const claims = {
  data: [
    ['A', 'B', 'C'],
    ['D', 'E', 'F', 'G'],
  ],
};

const disclosureFrame = {
  data: {
    0: {
      _sd: [0, 2], // `A` and `C` in data[0]
    },
  },
};

const result = {
  colors: [
    [
      { '...': 'kQv_QULrikI6mBs-1WmNeJZKNvf8dJNqio5QSJA_ZZY' },
      'B',
      { '...': 'zZ9am-i8OcoLC7p_Mc7jOm2ibr_6gklO57NCrxabR_0' },
    ],
    ['D', 'E', 'F', 'G'],
  ],
};
```

- Object in array

```ts
const claims = {
  foods: [
    {
      type: 'apple',
      number: 2,
    },
    'beef',
    'juice',
  ],
};

const disclosureFrame = {
  foods: {
    0: {
      _sd: ['type'], // `type` property of items[0]
    },
  },
};

const result = {
  foods: [
    {
      _sd: ['7aGqCE9HepzELBi59BvxxriDiV7uiB4yHTyN1im_m4M'],
      number: 2,
    },
    'beef',
    'juice',
  ],
};
```

- Decoy

```ts
const claims = {
  color: {
    title: '#232323',
    footer: '#121212',
    button: '#fefefe',
  },
};

const disclosureFrame = {
  color: {
    _sd: ['title', 'footer'],
    _sd_decoy: 1,
  },
};

const result = {
  color: {
    _sd: [
      'ErJnMnGG9-pyfTod0UvVKHGzVvU4h-VEZhOw2-Oi39Q',
      'A544ERLAEA5JKXFr62mg-G8fmxqgTFDigqYuiYpz_4E',
      'vH6Ut_jfOnYGphLIbFuiZFu4Uh0osveZ0npBbaim6n8',
    ],
    button: '#fefefe',
  },
};
```

**Note**: We are using JSON stringify for [disclosure format](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-06.html#disclosure_format_considerations)
