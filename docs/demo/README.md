# The README demo

`rowsafe-demo.gif` (and `.mp4`, `.webm`) is a real recording: a PostgreSQL 17 in
Docker with three planted problems (200 thousand dead rows, a duplicate index, a
session idle in a transaction), and a terminal that installs the CLI from
https://rowsafe.sh/cli, runs `rowsafe pulse`, fixes the two warnings with
`rowsafe fix` and runs `rowsafe pulse` again. No output is edited.

Record it again after the CLI's output changes:

```sh
docs/demo/record.sh
```

It needs Docker and takes about 12 minutes: pulse reports an idle transaction
only after 10 minutes. `demo.tape` is the script ([vhs](https://github.com/charmbracelet/vhs)),
`plant.sql` the planted problems, `compose.yaml` the database and the recorder.
