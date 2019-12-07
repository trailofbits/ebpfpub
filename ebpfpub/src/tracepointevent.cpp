#include "tracepointevent.h"
#include "uniquefd.h"

#include <algorithm>
#include <cassert>
#include <fstream>
#include <iostream>
#include <string>

namespace ebpfpub {
namespace {
const std::string kTracepointRootPath = "/sys/kernel/debug/tracing/events/";

const std::string kFormatSectionName{"format:"};
const std::string kFieldSectionName{"field:"};

const std::string kOffsetFieldName{"offset:"};
const std::string kSizeFieldName{"size:"};
const std::string kSignedFieldName{"signed:"};

bool configureTracepointEvent(const ITracepointEvent &tracepoint_event,
                              bool enable) {
  auto enable_switch_path_exp =
      tracepoint_event.path(ITracepointEvent::PathType::EnableSwitch);

  if (!enable_switch_path_exp.succeeded()) {
    return false;
  }

  auto enable_switch_path = enable_switch_path_exp.takeValue();

  std::fstream f(enable_switch_path, std::ios::out | std::ios::binary);

  if (!f) {
    return false;
  }

  f << (enable ? '1' : '0');
  if (!f) {
    return false;
  }

  return true;
}
} // namespace

struct TracepointEvent::PrivateData final {
  std::string category;
  std::string name;

  std::unordered_map<PathType, std::string> path_map;
  std::uint32_t event_identifier{0U};

  Structure structure;
  bool enabled{false};
};

TracepointEvent::~TracepointEvent() {
  if (!disable()) {
    std::cerr << "Failed to disable the tracepoint\n";
  }
}

const std::string &TracepointEvent::category() const { return d->category; }

const std::string &TracepointEvent::name() const { return d->name; }

StringErrorOr<std::string>
TracepointEvent::path(const TracepointEvent::PathType &path_type) const {

  auto path_it = d->path_map.find(path_type);
  if (path_it == d->path_map.end()) {
    return StringError::create("The specified path does not exists");
  }

  return path_it->second;
}

std::uint32_t TracepointEvent::eventIdentifier() const {
  return d->event_identifier;
}

const TracepointEvent::Structure &TracepointEvent::structure() const {
  return d->structure;
}

bool TracepointEvent::enable() {
  if (!configureTracepointEvent(*this, true)) {
    return false;
  }

  d->enabled = true;
  return true;
}

bool TracepointEvent::disable() {
  if (!d->enabled) {
    return true;
  }

  if (!configureTracepointEvent(*this, false)) {
    return false;
  }

  d->enabled = false;
  return true;
}

TracepointEvent::TracepointEvent(const std::string &category,
                                 const std::string &name)
    : d(new PrivateData) {

  d->category = category;
  d->name = name;

  d->path_map = getTracepointPathMap(category, name);

  // Convert the event identifier to number
  auto tracepoint_id_exp = readFile(d->path_map.at(PathType::EventIdentifier));

  if (!tracepoint_id_exp.succeeded()) {
    throw tracepoint_id_exp.error();
  }

  auto tracepoint_id = tracepoint_id_exp.takeValue();

  char *null_terminator{nullptr};
  d->event_identifier = static_cast<std::uint32_t>(
      std::strtoul(tracepoint_id.c_str(), &null_terminator, 10));

  if (null_terminator == nullptr ||
      (*null_terminator != 0 && *null_terminator != '\n')) {
    throw StringError::create("Failed to parse the event identifier");
  }

  // Read the tracepoint format
  auto tracepoint_format_exp = readFile(d->path_map.at(PathType::Format));

  if (!tracepoint_format_exp.succeeded()) {
    throw tracepoint_format_exp.error();
  }

  auto tracepoint_format = tracepoint_format_exp.takeValue();

  auto structure_exp = parseTracepointEventFormat(tracepoint_format);
  if (!structure_exp.succeeded()) {
    throw structure_exp.error();
  }

  d->structure = structure_exp.takeValue();
}

TracepointEvent::PathMap
TracepointEvent::getTracepointPathMap(const std::string &category,
                                      const std::string &name) {

  PathMap path_map;

  auto root_path = kTracepointRootPath + category + "/" + name;
  path_map.insert({PathType::Root, root_path});

  auto path = root_path + "/enable";
  path_map.insert({PathType::EnableSwitch, path});

  path = root_path + "/format";
  path_map.insert({PathType::Format, path});

  path = root_path + "/id";
  path_map.insert({PathType::EventIdentifier, path});

  return path_map;
}

StringErrorOr<std::string> TracepointEvent::readFile(const std::string &path) {
  // We can't use seek on the tracepoint format file
  std::ifstream input_file(path, std::ios::in | std::ios::binary);
  if (!input_file) {
    return StringError::create("Failed to open the file");
  }

  std::string output;
  std::array<char, 1024> read_buffer{};

  while (true) {
    input_file.read(read_buffer.data(), read_buffer.size());

    auto bytes_read = static_cast<std::size_t>(input_file.gcount());
    if (bytes_read == 0U) {
      break;
    }

    output.reserve(output.size() + bytes_read);
    output.append(read_buffer.data(), bytes_read);
  }

  if (!input_file.eof()) {
    return StringError::create("Failed to read file");
  }

  return output;
}

StringErrorOr<ITracepointEvent::StructureField>
TracepointEvent::parseTracepointEventFormatLine(
    const std::string &format_line) {

  // clang-format off
  /*
    Example

    =====

    unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
    int common_pid;	offset:4;	size:4;	signed:1;
    int __syscall_nr;	offset:8;	size:4;	signed:1;
  */
  // clang-format on

  TracepointEvent::StructureField output{};

  // Determine where each field starts and stops
  auto declaration_field_start = 0U;
  auto declaration_field_end = format_line.find(";");
  if (declaration_field_end == std::string::npos) {
    return StringError::create("Invalid format file");
  }

  auto offset_field_start = declaration_field_end + 1;
  auto offset_field_end = format_line.find(";", offset_field_start);
  if (offset_field_end == std::string::npos) {
    return StringError::create("Invalid format file");
  }

  auto size_field_start = offset_field_end + 1;
  auto size_field_end = format_line.find(";", size_field_start);
  if (size_field_end == std::string::npos) {
    return StringError::create("Invalid format file");
  }

  auto signed_field_start = size_field_end + 1;
  auto signed_field_end = format_line.find(";", signed_field_start);
  if (signed_field_end == std::string::npos) {
    return StringError::create("Invalid format file");
  }

  auto declaration_field = format_line.substr(
      declaration_field_start, declaration_field_end - declaration_field_start);

  // declaration field (type + name)
  auto name_field_start = declaration_field.find_last_of(" ");
  if (name_field_start == std::string::npos) {
    return StringError::create("Invalid format file");
  }

  output.type = declaration_field.substr(0U, name_field_start);
  output.name = declaration_field.substr(name_field_start + 1);

  // offset field
  auto offset_field = format_line.substr(offset_field_start,
                                         offset_field_end - offset_field_start);

  auto offset_field_value_index = offset_field.find(kOffsetFieldName);
  if (offset_field_value_index == std::string::npos) {
    return StringError::create("Invalid format file");
  }

  offset_field_value_index += kOffsetFieldName.size();

  char *string_end_ptr = nullptr;
  output.offset = std::strtoul(&offset_field.at(offset_field_value_index),
                               &string_end_ptr, 10);

  if (*string_end_ptr != 0) {
    return StringError::create("Invalid format file");
  }

  // size field
  auto size_field =
      format_line.substr(size_field_start, size_field_end - size_field_start);

  auto size_field_value_index = size_field.find(kSizeFieldName);

  if (size_field_value_index == std::string::npos) {
    return StringError::create("Invalid format file");
  }

  size_field_value_index += kSizeFieldName.size();

  string_end_ptr = nullptr;

  output.size =
      std::strtoul(&size_field.at(size_field_value_index), &string_end_ptr, 10);

  if (*string_end_ptr != 0) {
    return StringError::create("Invalid format file");
  }

  // signed field
  auto signed_field = format_line.substr(signed_field_start,
                                         signed_field_end - signed_field_start);

  auto signed_field_value_index = signed_field.find(kSignedFieldName);
  if (signed_field_value_index == std::string::npos) {
    return StringError::create("Invalid format file");
  }

  signed_field_value_index += kSignedFieldName.size();
  if (signed_field.at(signed_field_value_index) == '0') {
    output.is_signed = false;

  } else if (signed_field.at(signed_field_value_index) == '1') {
    output.is_signed = true;

  } else {
    return StringError::create("Invalid format file");
  }

  output.type = normalizeStructureFieldType(output.type);
  return output;
}

StringErrorOr<ITracepointEvent::Structure>
TracepointEvent::parseTracepointEventFormat(const std::string &format) {

  // clang-format off
  /*
    Example

    =====

    name: sys_enter_open
    ID: 606
    format:
      field:unsigned short common_type;	offset:0;	size:2;	signed:0;
      field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
      field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
      field:int common_pid;	offset:4;	size:4;	signed:1;

      field:int __syscall_nr;	offset:8;	size:4;	signed:1;
      field:const char * filename;	offset:16;	size:8;	signed:0;
      field:int flags;	offset:24;	size:8;	signed:0;
      field:umode_t mode;	offset:32;	size:8;	signed:0;

    print fmt: "filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))
  */
  // clang-format on

  TracepointEvent::Structure output;

  // Get the starting position
  auto format_section_index = format.find(kFormatSectionName);
  if (format_section_index == std::string::npos) {
    return StringError::create("Invalid format file");
  }

  format_section_index += kFormatSectionName.size();
  auto current_position = format_section_index;

  while (true) {
    // Look for the next "field:" string, and save the index where it ends
    auto field_section_start_index =
        format.find(kFieldSectionName, current_position);

    if (field_section_start_index == std::string::npos) {
      break;
    }

    field_section_start_index += kFieldSectionName.size();

    // Search for the field section terminator
    auto field_section_end_index = format.find("\n", field_section_start_index);
    if (field_section_end_index == std::string::npos) {
      return StringError::create("Invalid format file");
    }

    // Parse the line we have found
    auto current_line =
        format.substr(field_section_start_index,
                      field_section_end_index - field_section_start_index);

    auto struct_field_exp = parseTracepointEventFormatLine(current_line);

    if (!struct_field_exp.succeeded()) {
      return struct_field_exp.error();
    }

    auto struct_field = struct_field_exp.takeValue();
    output.push_back(std::move(struct_field));

    // Save the position for the next line
    current_position = field_section_end_index + 1;
  }

  return output;
}

std::string
TracepointEvent::normalizeStructureFieldType(const std::string &type) {
  // clang-format off
  static const std::vector<std::string> kBlacklistedKeywords = {
    "__attribute__((user))"
  };
  // clang-format on

  auto output_type = type;

  for (const auto &keyword : kBlacklistedKeywords) {
    while (true) {
      auto index = output_type.find(keyword);
      if (index == std::string::npos) {
        break;
      }

      output_type.erase(index, keyword.size());
    }
  }

  // clang-format off
  auto it =std::unique(
    output_type.begin(),
    output_type.end(),

    [](char lhs, char rhs) -> bool {
      return (lhs == rhs) && (lhs == ' ');
    }
  );
  // clang-format on

  output_type.erase(it, output_type.end());
  return output_type;
}

StringErrorOr<ITracepointEvent::Ref>
ITracepointEvent::create(const std::string &category, const std::string &name) {
  try {
    return Ref(new TracepointEvent(category, name));

  } catch (const std::bad_alloc &) {
    return StringError::create("Memory allocation failure");

  } catch (const StringError &error) {
    return error;
  }
}
} // namespace ebpfpub
