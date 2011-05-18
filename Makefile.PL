# $Id$
use 5.010000;
use ExtUtils::MakeMaker;
WriteMakefile(
    NAME => 'Mail::OpenDKIM',
    PREREQ_PM => {
   	 'Error' => 0,
	 'Test::More' => 0.82,	# Needs new_ok
	 'Carp' => 0,
	 },
    VERSION_FROM => 'lib/Mail/OpenDKIM.pm',
    AUTHOR => 'Nigel Horne <nigel@mailermailer.com>',
    ABSTRACT => 'Provides an interface to OpenDKIM C library',
    LIBS => ['-lopendkim'],
    INC => '-I/usr/local/include',
    OBJECT => '$(O_FILES)', # link all the C files too
    LICENSE => 'perl',
);

sub MY::postamble {
  return <<'MAKE_FRAG';
all :: README

README: lib/Mail/OpenDKIM.pm
	pod2text $> > README
MAKE_FRAG
}
