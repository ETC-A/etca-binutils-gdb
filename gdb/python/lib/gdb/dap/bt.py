# Copyright 2022-2023 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import gdb
import os
import itertools

from gdb.frames import frame_iterator
from gdb.FrameIterator import FrameIterator
from gdb.FrameDecorator import FrameDecorator
from .frames import frame_id
from .server import request, capability
from .startup import send_gdb_with_response, in_gdb_thread
from .state import set_thread


# Helper function to compute a stack trace.
@in_gdb_thread
def _backtrace(thread_id, levels, startFrame):
    set_thread(thread_id)
    frames = []
    if levels == 0:
        # Zero means all remaining frames.
        high = -1
    else:
        # frame_iterator uses an inclusive range, so subtract one.
        high = startFrame + levels - 1
    try:
        frame_iter = frame_iterator(gdb.newest_frame(), startFrame, high)
    except gdb.error:
        frame_iter = ()
    for current_frame in frame_iter:
        newframe = {
            "id": frame_id(current_frame),
            "name": current_frame.function(),
            # This must always be supplied, but we will set it
            # correctly later if that is possible.
            "line": 0,
            # GDB doesn't support columns.
            "column": 0,
            "instructionPointerReference": hex(current_frame.address()),
        }
        line = current_frame.line()
        if line is not None:
            newframe["line"] = line
        filename = current_frame.filename()
        if filename is not None:
            newframe["source"] = {
                "name": os.path.basename(filename),
                "path": filename,
                # We probably don't need this but it doesn't hurt
                # to be explicit.
                "sourceReference": 0,
            }
        frames.append(newframe)
    # Note that we do not calculate totalFrames here.  Its absence
    # tells the client that it may simply ask for frames until a
    # response yields fewer frames than requested.
    return {
        "stackFrames": frames,
    }


@request("stackTrace")
@capability("supportsDelayedStackTraceLoading")
def stacktrace(*, levels: int = 0, startFrame: int = 0, threadId: int, **extra):
    return send_gdb_with_response(lambda: _backtrace(threadId, levels, startFrame))
