use 5.010000;
use ExtUtils::MakeMaker;
WriteMakefile(
    NAME              => 'Mail::OpenDKIM',
    VERSION_FROM      => 'lib/Mail/OpenDKIM.pm', # finds $VERSION
    PREREQ_PM         => {
   	 'Error' => 0,
	 'Test::More' => 0.82,	# Needs new_ok
	 'Carp' => 0,
	 }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Mail/OpenDKIM.pm', # retrieve abstract from module
       AUTHOR         => 'Nigel Horne <nigel@mailermailer.com>') : ()),
    LIBS              => ['-lopendkim'], # e.g., '-lm'
    DEFINE            => '', # e.g., '-DHAVE_SOMETHING'
    INC               => '-I. -I/usr/local/include', # e.g., '-I. -I/usr/include/other'
	# Un-comment this if you add C files to link with later:
    OBJECT            => '$(O_FILES)', # link all the C files too
    LICENSE	      => 'perl',
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'MAIL-OpenDKIM-*' },
);
