package diag

import "golang.org/x/sys/unix"

type TCP struct {
	Diag
}

// TCP allows to read and alter TCP socker information.
func (d *Diag) TCP() *TCP {
	return &TCP{*d}
}

func (t *TCP) Dump() ([]Object, error) {
	var results []Object

	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		header := InetDiagReqV2{
			Family:   family,
			Protocol: unix.IPPROTO_TCP,
			States:   1 << 1,
		}
		objs, err := t.dump(header)
		if err != nil {
			return results, err
		}
		results = append(results, objs...)
	}

	return results, nil
}

type UDP struct {
	Diag
}

// UDP allows to read and alter UDP socker information.
func (d *Diag) UDP() *UDP {
	return &UDP{*d}
}

func (u *UDP) Dump() ([]Object, error) {
	var results []Object

	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		header := InetDiagReqV2{
			Family:   family,
			Protocol: unix.IPPROTO_UDP,
			States:   1 << 1,
		}
		objs, err := u.dump(header)
		if err != nil {
			return results, err
		}
		results = append(results, objs...)
	}

	return results, nil
}

type Raw struct {
	Diag
}

func (d *Diag) Raw() *Raw {
	return &Raw{*d}
}

func (r *Raw) Dump() ([]Object, error) {
	var results []Object

	for _, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		header := InetDiagReqV2{
			Family:   family,
			Protocol: unix.IPPROTO_RAW,
			States:   1 << 1,
		}
		objs, err := r.dump(header)
		if err != nil {
			return results, err
		}
		results = append(results, objs...)
	}

	return results, nil
}
