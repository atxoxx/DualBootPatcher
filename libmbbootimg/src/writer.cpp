/*
 * Copyright (C) 2017  Andrew Gunnerson <andrewgunnerson@gmail.com>
 *
 * This file is part of MultiBootPatcher
 *
 * MultiBootPatcher is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * MultiBootPatcher is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with MultiBootPatcher.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "mbbootimg/writer.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "mbcommon/file.h"
#include "mbcommon/file/filename.h"
#include "mbcommon/string.h"

#include "mbbootimg/entry.h"
#include "mbbootimg/file_p.h"
#include "mbbootimg/header.h"
#include "mbbootimg/writer_p.h"

// TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO
// TODO TODO TODO UPDATE DOCS TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO
// TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO

/*!
 * \typedef FormatReaderSetOption
 *
 * \brief Format reader callback to set option
 *
 * \param bir MbBiReader
 * \param userdata User callback data
 * \param key Option key
 * \param value Option value
 *
 * \return
 *   * Return #MB_BI_OK if the option was handled successfully
 *   * Return #MB_BI_WARN if the option cannot be handled
 *   * Return \<= #MB_BI_FAILED if an error occurs
 */

/*!
 * \typedef FormatReaderReadHeader
 *
 * \brief Format reader callback to read header
 *
 * \param[in] bir MbBiReader
 * \param[in] userdata User callback data
 * \param[out] header MbBiHeader instance to write header values
 *
 * \return
 *   * Return #MB_BI_OK if the header was successfully read
 *   * Return \<= #MB_BI_WARN if an error occurs
 */

/*!
 * \typedef FormatReaderReadEntry
 *
 * \brief Format reader callback to read next entry
 *
 * \note This callback *must* be able to skip to the next entry if the user does
 *       not read or finish reading the entry data with
 *       mb_bi_reader_read_data().
 *
 * \param[in] bir MbBiReader
 * \param[in] userdata User callback data
 * \param[out] entry MbBiEntry instance to write entry values
 *
 * \return
 *   * Return #MB_BI_OK if the entry was successfully read
 *   * Return \<= #MB_BI_WARN if an error occurs
 */

/*!
 * \typedef FormatReaderReadData
 *
 * \brief Format reader callback to read entry data
 *
 * \param[in] bir MbBiReader
 * \param[in] userdata User callback data
 * \param[out] buf Output buffer to write data
 * \param[in] buf_size Size of output buffer
 * \param[out] bytes_read Output number of bytes that were read. 0 indicates
 *                        end-of-file for the current entry.
 *
 * \return
 *   * Return #MB_BI_OK if the entry is successfully read
 *   * Return \<= #MB_BI_WARN if an error occurs
 */

/*!
 * \typedef FormatReaderFree
 *
 * \brief Format reader callback to clean up resources
 *
 * This function will be called during a call to mb_bi_reader_free(), regardless
 * of the current state. It is guaranteed to only be called once. The function
 * may return any valid status code, but the resources *must* be cleaned up.
 *
 * \param bir MbBiReader
 * \param userdata User callback data
 *
 * \return
 *   * Return #MB_BI_OK if the cleanup completes without error
 *   * Return \<= #MB_BI_WARN if an error occurs during cleanup
 */

///

MB_BEGIN_C_DECLS

static struct
{
    int code;
    const char *name;
    int (*func)(MbBiWriter *);
} writer_formats[] = {
    {
        MB_BI_FORMAT_ANDROID,
        MB_BI_FORMAT_NAME_ANDROID,
        mb_bi_writer_set_format_android
    }, {
        MB_BI_FORMAT_BUMP,
        MB_BI_FORMAT_NAME_BUMP,
        mb_bi_writer_set_format_bump
    }, {
        MB_BI_FORMAT_LOKI,
        MB_BI_FORMAT_NAME_LOKI,
        mb_bi_writer_set_format_loki
    }, {
        MB_BI_FORMAT_MTK,
        MB_BI_FORMAT_NAME_MTK,
        mb_bi_writer_set_format_mtk
    }, {
        MB_BI_FORMAT_SONY_ELF,
        MB_BI_FORMAT_NAME_SONY_ELF,
        mb_bi_writer_set_format_sony_elf
    }, {
        0,
        nullptr,
        nullptr
    },
};

int _mb_bi_writer_register_format(MbBiWriter *biw,
                                  void *userdata,
                                  int type,
                                  const char *name,
                                  FormatWriterSetOption set_option_cb,
                                  FormatWriterGetHeader get_header_cb,
                                  FormatWriterWriteHeader write_header_cb,
                                  FormatWriterGetEntry get_entry_cb,
                                  FormatWriterWriteEntry write_entry_cb,
                                  FormatWriterWriteData write_data_cb,
                                  FormatWriterClose close_cb,
                                  FormatWriterFree free_cb)
{
    WRITER_ENSURE_STATE(biw, WriterState::NEW);
    int ret;
    FormatWriter format;

    format.type = type;
    format.name = strdup(name);
    format.set_option_cb = set_option_cb;
    format.get_header_cb = get_header_cb;
    format.write_header_cb = write_header_cb;
    format.get_entry_cb = get_entry_cb;
    format.write_entry_cb = write_entry_cb;
    format.write_data_cb = write_data_cb;
    format.close_cb = close_cb;
    format.free_cb = free_cb;
    format.userdata = userdata;

    if (!format.name) {
        mb_bi_writer_set_error(biw, -errno, "%s", strerror(errno));
        ret = MB_BI_FAILED;
        goto done;
    }

    // Clear old format
    if (biw->format_set) {
        _mb_bi_writer_free_format(biw, &biw->format);
    }

    // Set new format
    biw->format = format;
    biw->format_set = true;

    ret = MB_BI_OK;

done:
    if (ret != MB_BI_OK) {
        int ret2 = _mb_bi_writer_free_format(biw, &format);
        if (ret2 < ret) {
            ret = ret2;
        }
    }

    return ret;
}

int _mb_bi_writer_free_format(MbBiWriter *biw, FormatWriter *format)
{
    WRITER_ENSURE_STATE(biw, WriterState::ANY);
    int ret = MB_BI_OK;

    if (format) {
        if (format->free_cb) {
            ret = format->free_cb(biw, format->userdata);
        }

        free(format->name);
    }

    return ret;
}

/*!
 * \brief Allocate new MbBiWriter.
 *
 * \return New MbBiWriter or NULL if memory could not be allocated. If the
 *         function fails, `errno` will be set accordingly.
 */
MbBiWriter * mb_bi_writer_new()
{
    MbBiWriter *biw = static_cast<MbBiWriter *>(calloc(1, sizeof(MbBiWriter)));
    if (biw) {
        biw->state = WriterState::NEW;
        biw->header = mb_bi_header_new();
        biw->entry = mb_bi_entry_new();

        if (!biw->header || !biw->entry) {
            mb_bi_header_free(biw->header);
            mb_bi_entry_free(biw->entry);
            free(biw);
            biw = nullptr;
        }
    }
    return biw;
}

/*!
 * \brief Free an MbBiWriter.
 *
 * If the writer has not been closed, it will be closed and the result of
 * mb_bi_writer_close() will be returned. Otherwise, #MB_BI_OK will be returned.
 * Regardless of the return value, the writer will always be freed and should no
 * longer be used.
 *
 * \param biw MbBiWriter
 * \return The result of mb_bi_writer_close() if the boot image has not
 *         been closed; otherwise, #MB_BI_OK.
 */
int mb_bi_writer_free(MbBiWriter *biw)
{
    int ret = MB_BI_OK, ret2;

    if (biw) {
        if (biw->state != WriterState::CLOSED) {
            ret = mb_bi_writer_close(biw);
        }

        if (biw->format_set) {
            ret2 = _mb_bi_writer_free_format(biw, &biw->format);
            if (ret2 < ret) {
                ret = ret2;
            }
        }

        mb_bi_header_free(biw->header);
        mb_bi_entry_free(biw->entry);

        free(biw->error_string);
        free(biw);
    }

    return ret;
}

/*!
 * Open boot image from filename (MBS).
 *
 * \param biw MbBiWriter
 * \param filename MBS filename
 *
 * \return
 *   * #MB_BI_OK if the boot image was successfully opened
 *   * \<= #MB_BI_WARN if an error occurs
 */
int mb_bi_writer_open_filename(MbBiWriter *biw, const char *filename)
{
    WRITER_ENSURE_STATE(biw, WriterState::NEW);
    int ret;

    MbFile *file = mb_file_new();
    if (!file) {
        mb_bi_writer_set_error(biw, MB_BI_ERROR_INTERNAL_ERROR,
                               "%s", strerror(errno));
        return MB_BI_FAILED;
    }

    ret = mb_file_open_filename(file, filename, MB_FILE_OPEN_WRITE_ONLY);
    if (ret != MB_FILE_OK) {
        // Always return MB_BI_FAILED as MB_FILE_FATAL would not affect us
        // at this point
        mb_bi_writer_set_error(biw, mb_file_error(file),
                               "Failed to open for writing: %s",
                               mb_file_error_string(file));
        mb_file_free(file);
        return MB_BI_FAILED;
    }

    return mb_bi_writer_open(biw, file, true);
}

/*!
 * Open boot image from filename (WCS).
 *
 * \param biw MbBiWriter
 * \param filename WCS filename
 *
 * \return
 *   * #MB_BI_OK if the boot image was successfully opened
 *   * \<= #MB_BI_WARN if an error occurs
 */
int mb_bi_writer_open_filename_w(MbBiWriter *biw, const wchar_t *filename)
{
    WRITER_ENSURE_STATE(biw, WriterState::NEW);
    int ret;

    MbFile *file = mb_file_new();
    if (!file) {
        mb_bi_writer_set_error(biw, MB_BI_ERROR_INTERNAL_ERROR,
                               "%s", strerror(errno));
        return MB_BI_FAILED;
    }

    ret = mb_file_open_filename_w(file, filename, MB_FILE_OPEN_WRITE_ONLY);
    if (ret != MB_FILE_OK) {
        // Always return MB_BI_FAILED as MB_FILE_FATAL would not affect us
        // at this point
        mb_bi_writer_set_error(biw, mb_file_error(file),
                               "Failed to open for writing: %s",
                               mb_file_error_string(file));
        mb_file_free(file);
        return MB_BI_FAILED;
    }

    return mb_bi_writer_open(biw, file, true);
}

/*!
 * Open boot image from MbFile handle.
 *
 * If \p owned is true, then the MbFile handle will be closed and freed when the
 * MbBiWriter is closed and freed.
 *
 * \note If this function fails, \p file will be untouched and must be closed
 *       and freed by the caller.
 *
 * \param biw MbBiWriter
 * \param file MbFile handle
 * \param owned Whether the MbBiWriter should take ownership of the MbFile
 *              handle
 *
 * \return
 *   * #MB_BI_OK if the boot image was successfully opened
 *   * \<= #MB_BI_WARN if an error occurs
 */
int mb_bi_writer_open(MbBiWriter *biw, MbFile *file, bool owned)
{
    WRITER_ENSURE_STATE(biw, WriterState::NEW);

    if (!biw->format_set) {
        mb_bi_writer_set_error(biw, MB_BI_ERROR_PROGRAMMER_ERROR,
                               "No writer format registered");
        return MB_BI_FAILED;
    }

    biw->file = file;
    biw->file_owned = owned;
    biw->state = WriterState::HEADER;

    return MB_BI_OK;
}

/*!
 * \brief Close an MbBiWriter.
 *
 * This function will close an MbBiWriter if it is open. Regardless of the
 * return value, the writer is closed and can no longer be used for further
 * operations. It should be freed with mb_bi_writer_free().
 *
 * \param biw MbBiWriter
 *
 * \return
 *   * #MB_BI_OK if no error was encountered when closing the writer.
 *   * \<= #MB_BI_WARN if the writer is opened and an error occurs while
 *     closing the writer
 */
int mb_bi_writer_close(MbBiWriter *biw)
{
    int ret = MB_FILE_OK;

    // Allow any state since mb_bi_writer_free() will call
    // mb_bi_writer_close()
    WRITER_ENSURE_STATE(biw, WriterState::ANY);

    // Avoid double-closing or closing nothing
    if (!(biw->state & (WriterState::CLOSED | WriterState::NEW))) {
        if (biw->file && biw->file_owned) {
            ret = mb_file_free(biw->file);
        }

        biw->file = nullptr;
        biw->file_owned = false;

        // Don't change state to WriterState::FATAL if MB_BI_FATAL is returned.
        // Otherwise, we risk double-closing the boot image. CLOSED and FATAL
        // are the same anyway, aside from the fact that boot images can be
        // closed in the latter state.
    }

    biw->state = WriterState::CLOSED;

    return ret;
}

/*!
 * \brief Read boot image header
 *
 * Read the header from the boot image and store the header values to an
 * MbBiHeader instance allocated by the caller. The caller is responsible for
 * deallocating \p header when it is no longer needed.
 *
 * \param[in] biw MbBiWriter
 * \param[out] header Pointer to MbBiHeader for storing header values
 *
 * \return
 *   * #MB_BI_OK if the boot image header is successfully read
 *   * \<= #MB_BI_WARN if an error occurs
 */
int mb_bi_writer_get_header(MbBiWriter *biw, MbBiHeader **header)
{
    WRITER_ENSURE_STATE(biw, WriterState::HEADER);
    int ret;

    if (!biw->format.get_header_cb) {
        mb_bi_writer_set_error(biw, MB_BI_ERROR_INTERNAL_ERROR,
                               "Missing format get_header_cb");
        biw->state = WriterState::FATAL;
        return MB_BI_FATAL;
    }

    ret = biw->format.get_header_cb(biw, biw->format.userdata, header);
    if (ret == MB_BI_OK) {
        biw->state = WriterState::ENTRY;
    } else if (ret <= MB_BI_FATAL) {
        biw->state = WriterState::FATAL;
    }

    return ret;
}

/*!
 * \brief Read boot image header
 *
 * Read the header from the boot image and store the header values to an
 * MbBiHeader instance allocated by the caller. The caller is responsible for
 * deallocating \p header when it is no longer needed.
 *
 * \param[in] biw MbBiWriter
 * \param[out] header Pointer to MbBiHeader for storing header values
 *
 * \return
 *   * #MB_BI_OK if the boot image header is successfully read
 *   * \<= #MB_BI_WARN if an error occurs
 */
int mb_bi_writer_write_header(MbBiWriter *biw, MbBiHeader *header)
{
    WRITER_ENSURE_STATE(biw, WriterState::HEADER);
    int ret;

    if (!biw->format.write_header_cb) {
        mb_bi_writer_set_error(biw, MB_BI_ERROR_INTERNAL_ERROR,
                               "Missing format write_header_cb");
        biw->state = WriterState::FATAL;
        return MB_BI_FATAL;
    }

    ret = biw->format.write_header_cb(biw, biw->format.userdata, header);
    if (ret == MB_BI_OK) {
        biw->state = WriterState::ENTRY;
    } else if (ret <= MB_BI_FATAL) {
        biw->state = WriterState::FATAL;
    }

    return ret;
}

/*!
 * \brief Read next boot image entry
 *
 * Read the next entry from the boot image and store the entry values to an
 * MbBiEntry instance allocated by the caller. The caller is responsible for
 * deallocating \p entry when it is no longer needed.
 *
 * \param[in] biw MbBiWriter
 * \param[out] entry Pointer to MbBiEntry for storing entry values
 *
 * \return
 *   * #MB_BI_OK if the boot image entry is successfully read
 *   * #MB_BI_EOF if the boot image has no more entries
 *   * \<= #MB_BI_WARN if an error occurs
 */
int mb_bi_writer_get_entry(MbBiWriter *biw, MbBiEntry **entry)
{
    WRITER_ENSURE_STATE(biw, WriterState::ENTRY | WriterState::DATA);
    int ret;

    if (!biw->format.get_entry_cb) {
        mb_bi_writer_set_error(biw, MB_BI_ERROR_INTERNAL_ERROR,
                               "Missing format get_entry_cb");
        biw->state = WriterState::FATAL;
        return MB_BI_FATAL;
    }

    ret = biw->format.get_entry_cb(biw, biw->format.userdata, entry);
    if (ret == MB_BI_OK) {
        biw->state = WriterState::ENTRY;
    } else if (ret <= MB_BI_FATAL) {
        biw->state = WriterState::FATAL;
    }

    return ret;
}

/*!
 * \brief Read next boot image entry
 *
 * Read the next entry from the boot image and store the entry values to an
 * MbBiEntry instance allocated by the caller. The caller is responsible for
 * deallocating \p entry when it is no longer needed.
 *
 * \param[in] biw MbBiWriter
 * \param[out] entry Pointer to MbBiEntry for storing entry values
 *
 * \return
 *   * #MB_BI_OK if the boot image entry is successfully read
 *   * #MB_BI_EOF if the boot image has no more entries
 *   * \<= #MB_BI_WARN if an error occurs
 */
int mb_bi_writer_write_entry(MbBiWriter *biw, MbBiEntry *entry)
{
    WRITER_ENSURE_STATE(biw, WriterState::ENTRY | WriterState::DATA);
    int ret;

    if (!biw->format.write_entry_cb) {
        mb_bi_writer_set_error(biw, MB_BI_ERROR_INTERNAL_ERROR,
                               "Missing format write_entry_cb");
        biw->state = WriterState::FATAL;
        return MB_BI_FATAL;
    }

    ret = biw->format.write_entry_cb(biw, biw->format.userdata, entry);
    if (ret == MB_BI_OK) {
        biw->state = WriterState::ENTRY;
    } else if (ret <= MB_BI_FATAL) {
        biw->state = WriterState::FATAL;
    }

    return ret;
}

/*!
 * \brief Read current boot image entry data
 *
 * \param[in] biw MbBiWriter
 * \param[in] buf Input buffer
 * \param[in] size Size of input buffer
 * \param[out] bytes_written Pointer to store number of bytes written
 *
 * \return
 *   * #MB_BI_OK if data has been read
 *   * #MB_BI_EOF if EOF has been reached for the current entry
 *   * \<= #MB_BI_WARN if an error occurs
 */
int mb_bi_writer_write_data(MbBiWriter *biw, const void *buf, size_t size,
                            size_t *bytes_written)
{
    WRITER_ENSURE_STATE(biw, WriterState::DATA);
    int ret;

    if (!biw->format.write_data_cb) {
        mb_bi_writer_set_error(biw, MB_BI_ERROR_INTERNAL_ERROR,
                               "Missing format write_data_cb");
        biw->state = WriterState::FATAL;
        return MB_BI_FATAL;
    }

    ret = biw->format.write_data_cb(biw, biw->format.userdata, buf, size,
                                    bytes_written);
    if (ret == MB_BI_OK) {
        biw->state = WriterState::ENTRY;
    } else if (ret <= MB_BI_FATAL) {
        biw->state = WriterState::FATAL;
    }

    return ret;
}

/*!
 * \brief Get detected or forced boot image format code
 *
 * * If mb_bi_reader_enable_format_*() was used, then the detected boot image
 *   format code is returned.
 * * If mb_bi_reader_set_format() was used, then the forced boot image format
 *   code is returned.
 *
 * \note The return value is meaningful only after the boot image has been
 *       successfully opened. Otherwise, an error will be returned.
 *
 * \param biw MbBiWriter
 *
 * \return Boot image format code or -1 if the boot image is not open
 */
int mb_bi_writer_format_code(MbBiWriter *biw)
{
    if (!biw->format_set) {
        mb_bi_writer_set_error(biw, MB_BI_ERROR_PROGRAMMER_ERROR,
                               "No format selected");
        return -1;
    }

    return biw->format.type;
}

/*!
 * \brief Get detected or forced boot image format name
 *
 * * If mb_bi_reader_enable_format_*() was used, then the detected boot image
 *   format name is returned.
 * * If mb_bi_reader_set_format() was used, then the forced boot image format
 *   name is returned.
 *
 * \note The return value is meaningful only after the boot image has been
 *       successfully opened. Otherwise, an error will be returned.
 *
 * \param biw MbBiWriter
 *
 * \return Boot image format name or NULL if the boot image is not open
 */
const char * mb_bi_writer_format_name(MbBiWriter *biw)
{
    if (!biw->format_set) {
        mb_bi_writer_set_error(biw, MB_BI_ERROR_PROGRAMMER_ERROR,
                               "No format selected");
        return NULL;
    }

    return biw->format.name;
}

/*!
 * \brief Enable support for a boot image format by its code
 *
 * \param biw MbBiWriter
 * \param code Boot image format code
 *
 * \return
 *   * #MB_BI_OK if the format was successfully enabled
 *   * \<= #MB_BI_WARN if an error occurs
 */
int mb_bi_writer_set_format_by_code(MbBiWriter *biw, int code)
{
    WRITER_ENSURE_STATE(biw, WriterState::NEW);

    for (auto it = writer_formats; it->func; ++it) {
        if ((code & MB_BI_FORMAT_BASE_MASK)
                == (it->code & MB_BI_FORMAT_BASE_MASK)) {
            return it->func(biw);
        }
    }

    mb_bi_writer_set_error(biw, MB_BI_ERROR_PROGRAMMER_ERROR,
                           "Invalid format code: %d", code);
    return MB_BI_FAILED;
}

/*!
 * \brief Enable support for a boot image format by its name
 *
 * \param biw MbBiWriter
 * \param name Boot image format name
 *
 * \return
 *   * #MB_BI_OK if the format was successfully enabled
 *   * \<= #MB_BI_WARN if an error occurs
 */
int mb_bi_writer_set_format_by_name(MbBiWriter *biw, const char *name)
{
    WRITER_ENSURE_STATE(biw, WriterState::NEW);

    for (auto it = writer_formats; it->func; ++it) {
        if (strcmp(name, it->name) == 0) {
            return it->func(biw);
        }
    }

    mb_bi_writer_set_error(biw, MB_BI_ERROR_PROGRAMMER_ERROR,
                           "Invalid format name: %s", name);
    return MB_BI_FAILED;
}

/*!
 * \brief Get error code for a failed operation.
 *
 * \note The return value is undefined if an operation did not fail.
 *
 * \param biw MbBiWriter
 *
 * \return Error code for failed operation. If \>= 0, then the value is one of
 *         the MB_BI_* entries. If \< 0, then the error code is
 *         implementation-defined (usually `-errno` or `-GetLastError()`).
 */
int mb_bi_writer_error(MbBiWriter *biw)
{
    return biw->error_code;
}

/*!
 * \brief Get error string for a failed operation.
 *
 * \note The return value is undefined if an operation did not fail.
 *
 * \param biw MbBiWriter
 *
 * \return Error string for failed operation. The string contents may be
 *         undefined, but will never be NULL or an invalid string.
 */
const char * mb_bi_writer_error_string(MbBiWriter *biw)
{
    return biw->error_string ? biw->error_string : "";
}

/*!
 * \brief Set error string for a failed operation.
 *
 * \sa mb_bi_writer_set_error_v()
 *
 * \param biw MbBiWriter
 * \param error_code Error code
 * \param fmt `printf()`-style format string
 * \param ... `printf()`-style format arguments
 *
 * \return MB_BI_OK if the error was successfully set or MB_BI_FAILED if an
 *         error occured
 */
int mb_bi_writer_set_error(MbBiWriter *biw, int error_code,
                           const char *fmt, ...)
{
    int ret;
    va_list ap;

    va_start(ap, fmt);
    ret = mb_bi_writer_set_error_v(biw, error_code, fmt, ap);
    va_end(ap);

    return ret;
}

/*!
 * \brief Set error string for a failed operation.
 *
 * \sa mb_bi_writer_set_error()
 *
 * \param biw MbBiWriter
 * \param error_code Error code
 * \param fmt `printf()`-style format string
 * \param ap `printf()`-style format arguments as a va_list
 *
 * \return MB_BI_OK if the error was successfully set or MB_BI_FAILED if an
 *         error occured
 */
int mb_bi_writer_set_error_v(MbBiWriter *biw, int error_code,
                             const char *fmt, va_list ap)
{
    free(biw->error_string);

    char *dup = mb_format_v(fmt, ap);
    if (!dup) {
        return MB_BI_FAILED;
    }

    biw->error_code = error_code;
    biw->error_string = dup;
    return MB_BI_OK;
}

MB_END_C_DECLS
