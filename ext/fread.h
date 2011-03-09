#ifndef _FREAD_H
# define _FREAD_H

void		*fread_create  (const char * /* filename */, int /* flags */);
void		*fread_assoc   (FILE *, const char * /* filename */, int /* flags */, int /* close FILE on destroy */);

#define FREAD_NULL      0
#define FREAD_NONL      1
#define FREAD_NOCRNL    2
#define FREAD_NOCR      3

int		 fread_getline (void * /* handle */, char ** /* buf */);
void		 fread_destroy (void * /* handle */);
const char	*fread_filename(void * /* handle */);
unsigned int	 fread_lineno  (void * /* handle */);

#endif
