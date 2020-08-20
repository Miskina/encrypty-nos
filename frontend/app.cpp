#include "app.h"

#include "main_frame.h"

#include <openssl/evp.h>
#include <openssl/err.h>

wxIMPLEMENT_APP(app);

app::app()
{
}



bool app::OnInit()
{
	this->main_frame_ = new main_frame();
	this->main_frame_->Show(true);
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	return true;
}

int app::OnExit()
{
	/* Removes all digests and ciphers */
  EVP_cleanup();

  /* if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations */
  CRYPTO_cleanup_all_ex_data();

  /* Remove error strings */
  ERR_free_strings();
  
  return 0;
}

