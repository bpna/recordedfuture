@load base/frameworks/intel

module DetectBaddies;

export {
    redef enum Log::ID += {LOG};
    type Val: record {
        src_ip: addr;
        dst_ip: addr;
    };
}

event watchlistentry(description: Input::EventDescription, t: Input::Event,
                     data: Val) {
    local s: Intel::Seen = [$indicator_type=Intel::ADDR, $host=data$dst_ip, $where=Intel::IN_ANYWHERE];
    Intel::seen(s);
}

event zeek_init() {
    Input::add_event([$source="watchlist.file", $name="watchlist",
                      $fields=Val, $ev=watchlistentry]);
}
