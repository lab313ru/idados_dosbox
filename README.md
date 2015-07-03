# idados_dosbox
idados debugger plugin (DOSBOX+IDA)

## Compilation (Visual Studio 2013)
1. Put both "**idados**" and "**dosbox**" dirs in your **IDASDK\plugins\** directory;
2. Open **IDASDK\plugins\dosbox\visualc_net\dosbox.sln** and build it;
3. Open **IDASDK\plugins\idados\idados.sln** and build it;
4. Put generated **idados.plw** in **IDA\plugins\** directory;
5. Put generated **dosbox.exe** in **IDA\** directory (or create standalone dir somewhere, and put **ida.wll** and **dosbox.exe** there).

## Usage
1. Run **dosbox.exe**;
2. Mount some directory (**mount Y d:\somedir\**), put your *MS-DOS* executable in "**d:\somedir\**";
3. Goto your mounted **Y:\** disk (**Y:**);
4. Run "**debug yourexe.exe**". It will freeze. Just press *Alt+Tab*;
5. Open **IDA Pro** and your executable there;
6. Select "**Remote Dosbox debugger**";
7. Go to **Debugger->Process options...** menu and specify host as "**localhost**";
8. Press **F9** to run debugging process.
