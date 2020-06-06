module DetectBaddies;

export {
  type Idx: record {
    src_ip: addr;
  };

  type Val: record {
    dst_ip: addr;
  };
}

global watchlist: table[addr] of Val = table();

event zeek_init() {
  Input::add_table([$source="watchlist.file", $name="watchlist",
                    $idx=Idx, $val=Val, $destination=watchlist]);
  Input::remove("watchlist");
}
