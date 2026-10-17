# The README demo. Record it with ./record.sh, which starts the database
# this connects to (compose.yaml) and plants its problems first.

Output rowsafe-demo.gif
Output rowsafe-demo.mp4
Output rowsafe-demo.webm

Require curl

Set Shell bash
Set FontFamily "JetBrains Mono"
Set FontSize 15
Set LineHeight 1.15
Set Width 1180
Set Height 940
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms
Set WaitTimeout 2m
Set WaitPattern /^\$ *$/

# The password comes from PGPASSWORD, so it stays out of the recording.
Hide
Type "export PS1='$ ' PGPASSWORD=demo && clear"
Enter
Show

Type "curl -fsSL https://rowsafe.sh/cli | sh"
Sleep 300ms
Enter
Wait
Sleep 2s

Hide
Type "clear"
Enter
Show
Type "rowsafe add shop postgres://postgres@db/shop"
Sleep 300ms
Enter
Wait
Sleep 1500ms
Type "rowsafe pulse shop"
Sleep 300ms
Enter
Wait
Sleep 7s

Hide
Type "clear"
Enter
Show
Type "rowsafe fix shop idle_in_transaction --yes"
Sleep 300ms
Enter
Wait
Sleep 1500ms
Type "rowsafe fix shop vacuum_behind --yes"
Sleep 300ms
Enter
Wait
Sleep 2500ms

Hide
Type "clear"
Enter
Show
Type "rowsafe pulse shop"
Sleep 300ms
Enter
Wait
Sleep 5s
