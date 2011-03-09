drop table "hostname";
drop table "hostname_alias";

create table "hostname"(
	"host"		inet not null,
	"addrfam"	int2 not null default 0,
	"type"		int2 not null default 0,
	"data"		varchar(220) not null
);

create table "hostname_alias"(
	"alias"		varchar(220) not null,
	"hostname"	varchar(220) not null
);
