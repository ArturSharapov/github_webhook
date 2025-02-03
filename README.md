### Example

```
import { webhook } from './mod.ts';

const secret = 'secret';

webhook(secret)
  .on('star', (_) => console.log('stars:', _.repository.stargazers_count))
  .listen(3000);
```
