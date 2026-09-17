
CREATE TYPE plugins AS ENUM
    ('syscalls', 'filetracer', 'fileextractor', 'memdump', 'procmon', 'procdump2', 'cpuidmon', 'debugmon', 'ipt', 'hidsim', 'ptracemon', 'ebpfmon', 'unixsocketmon', 'apimon', 'regmon', 'socketmon', 'tlsmon', 'rootkitmon');


ALTER TABLE jobs
    ADD COLUMN plugins plugins[];