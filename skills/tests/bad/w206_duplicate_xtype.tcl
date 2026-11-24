# expect:W206
Rule {
    Reaction    BLOCK
    Severity    MAJOR
    Group       "Custom Expert Rules"
    Description "Duplicate AggregateMatch xtype"
    Target {
        Match FILE {
            Include AggregateMatch -xtype "T1" { -v "a" }
            Include AggregateMatch -xtype "T1" { -v "b" }
        }
    }
}
