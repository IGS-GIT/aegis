#ifndef LANDLOCK_SANDBOX_H
#define LANDLOCK_SANDBOX_H

#include <stdbool.h>

/**
 * Configure and enforce Landlock filesystem isolation on the current process.
 *
 * @param game_dir       The path to the game directory (granted READ + EXECUTE).
 * @param writable_dir   Optional path for save files/cache (granted READ + WRITE). May be NULL.
 * @return 0 on success, negative error code on failure.
 */
int apply_landlock_sandbox(const char *game_dir, const char *writable_dir);

#endif /* LANDLOCK_SANDBOX_H */
