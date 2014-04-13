robot_odyssey_patcher
=====================

A little modified version of Scanlim/Micah's patch which works with NASM version 2.11.02 (the latest version at the time of writing)

The original post is here: http://scanlime.org/2009/04/a-binary-patch-for-robot-odyssey/
Micah's original patch is here: http://tinyurl.com/ropatch

Micah's original patch was written quite some time ago (year 2009), which is excellent and does all the hardwork of patching. However, there is a little problem when I tried it with NASM version 2.11.02, it has assertion failures when patching the Shift key portion. I fiddled with the code a bit and found the problem seems to be nasm's alignment in code generation, which results in length mismatch. I thus changed the code a bit and made it work with the latest NASM. After the modification, I tried play the game, which worked so far.

The initial commit of the python code is Michah's original version, and the latest commit is the modified version.

Needless to say, credits definitely goes to Micah.
