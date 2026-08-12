# RAM-Standby-Cache-Memory-Cleaner-Script
Powershell script based on RAMMap Microsoft program that Empties the Standby Cached memory for RAM on a configurable loop.

Is your game Crashing or experiencing lagging/performance issues?

Then this might be the fix for you!

I started my journey of fixing this by using a program for developers called RAMMap.  The operating system can basically tell all active programs to just empty out their standby memory (Including cashed memory) using a feature called Empty Standby List.

I first tested this by running this command twice every 2 hours while I was playing and the problem completely went away.

This powershell script simply takes that function and runs it on a customizable loop (default is 5 minutes but is changeable for faster/slower machines) while you play the game.

The result is that my game runs smoother and never crashes anymore due to cached memory issues!

I hope this can help everyone with their problems not only running this game but potentially other games too!

This program is based off of this Microsoft sys internals program called RAMMap found here:
https://learn.microsoft.com/en-us/sysinternals/downloads/rammap
