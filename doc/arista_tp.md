arista traffic-policy rendering notes

## supported tokens

the following tokens are supported:
 - `action`
 - `address`
 - `comment`
 - `counter`
 - `destination-address`
 - `destination-exclude`
 - `destination-port`
 - `destination-prefix` - this should resolve to a configured field-set in traffic-policy format.
 - `fragment-offset`
 - `icmp-type`
 - `logging`
- `option`
   - `established`
   - `tcp-established`
   - `sample` (unsupported) - this is not a match criteria
   - `initial`
   - `rst`
   - `first-fragment` - this  will be rendered as a `fragment` match.`
 - `packet-length`
 - `source-address`
 - `source-exclude`
 - `source-port`
 - `source-prefix` - this should resolve to a configured field-set in traffic-policy format.
 - `verbatim`

## arista traffic-policy token use notes
### action

the fully supported actions are: `accept`, and `deny`.  use of `reject`, or `reject-with-tcp-rst` will result in the generation of deny actions in the rendered traffic policy.

### address token
use of the 'address' token will create (2) match terms in traffic-policy format. one to match source addresses and one to match destination addresses.  the balance of the fields in the term will be copied and rendered, exactly. use the address token with caution.

### counters

- if counters are specified in a term, a traffic-policy named-counter stanza will be generated in the rendered output.
- counter names should not contain a (`.`). if a (`.`) is embedded in a counter name it will be replaced w/a dash (`-`).

### (source|destination)-address-exclude

currently (as of 20201223), EOS does not support the use of 'except' within match statements.  if an exclude/except token is used, a field-set will be generated and rendered in the match-term output. this field-set will be named `<direction>-<term.name>` where direction is either **src** or **dst** depending on the direction of the token in use.

# TODO
