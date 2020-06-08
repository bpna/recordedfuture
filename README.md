# recordedfuture
My submission for the Recorded Future technical challenge

## How To
To run, first make sure the Recorded Future API python module is installed with `pip install rfapi`

Then, in your local clone

1. Run `python get_risklist.py` to get an IP risklist in zeek consumable format in a file named `zeek_intel.txt`.
2. Run `python get_demoevents.py` to get IP demo events in zeek consumable format in a file named `watchlist.file`.
3. Move `events.zeek` to `$ZEEKINSTALLDIR/share/zeek/site/`
4. Add the following lines to `$ZEEKINSTALLDIR/share/zeek/site/local.zeek`:
```
  @load policy/frameworks/intel/seen
  @load events

  redef Intel::read_files += {
     "[clone-dir]/zeek_intel.txt",
  };
```

Make sure to replace `$ZEEKINSTALLDIR` and `[clone-dir]` with the root install directory for zeek and the directory containing the clone of this repo, respectively.

Then run `zeekctl`, `install`, and `start` and voila! you have an `intel.log` file containing matches between the demo event and risk list data.
