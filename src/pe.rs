use std::io::prelude::*;
use std::{isize, path::PathBuf};

use thiserror::Error;

use crate::types::{
    DLL_NAME, IMAGE_DIRECTORY_ENTRY, IMAGE_DOS_HEADER, IMAGE_FILE_HEADER, IMAGE_IMPORT_BY_NAME,
    IMAGE_IMPORT_BY_NAME_EXTENDED, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_HEADERS64,
    IMAGE_OPTIONAL_HEADER64, IMAGE_SECTION_HEADER, IMAGE_THUNK_DATA64, Import,
};

#[derive(Error, Debug)]
pub enum PeError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("Invalid 64bit PE file.")]
    Invalid,
    #[error("RVA is not inside of a section.")]
    NotInSection,
    #[error("Section doesn't exist.")]
    NoSection,
    #[error("Descriptor doesn't exist.")]
    NoDescriptor,
}

trait Align<T> {
    /// Aligns a value to a specified boundary.
    ///
    /// This function rounds up a value to the next multiple of the specified alignment.
    fn align(&self, alignment: T) -> T;
}

// Generic implementation for any type that supports the required operations
impl<T> Align<T> for T
where
    T: Copy
        + std::ops::Rem<Output = T>
        + std::ops::Div<Output = T>
        + std::ops::Add<Output = T>
        + std::ops::Mul<Output = T>
        + PartialEq<T>
        + From<u8>,
{
    fn align(&self, alignment: T) -> T {
        if *self % alignment == T::from(0) {
            return *self;
        }

        (*self / alignment + T::from(1)) * alignment
    }
}

type Result<T> = std::result::Result<T, PeError>;

/// This is an abstraction of a PE file on disk.
pub struct Pe {
    bytes: Vec<u8>,
}

impl Pe {
    pub fn from(path: PathBuf) -> Result<Self> {
        Ok(Self {
            bytes: std::fs::read(path)?,
        })
    }

    pub fn get_dos_header(&self) -> IMAGE_DOS_HEADER {
        unsafe { (self.bytes.as_ptr() as *const IMAGE_DOS_HEADER).read_unaligned() }
    }

    pub fn get_nt_headers_ptr(&self) -> *const IMAGE_NT_HEADERS64 {
        // get the dos header so we can find the nt headers through it.
        let dos_header = self.get_dos_header();

        unsafe { self.bytes.as_ptr().add(dos_header.e_lfanew as _) as *const IMAGE_NT_HEADERS64 }
    }

    pub fn get_nt_headers(&self) -> IMAGE_NT_HEADERS64 {
        unsafe { self.get_nt_headers_ptr().read_unaligned() }
    }

    /// Ensure that this is actually a PE file.
    pub fn verify(&self) -> Result<()> {
        // make sure the DOS header magic number is valid.
        if self.get_dos_header().e_magic != 0x5A4D {
            return Err(PeError::Invalid);
        }

        // ensure that both fields have their magic numbers correctly set.
        if self.get_nt_headers().Signature != 0x4550
            || self.get_nt_headers().OptionalHeader.Magic != 0x20B
        {
            return Err(PeError::Invalid);
        }

        Ok(())
    }

    // NOTE: this absolutely should marked as `&mut self`.
    pub fn get_section_headers(&self) -> Result<&mut [IMAGE_SECTION_HEADER]> {
        //  get the address of the optional header which is right before the section header.
        let optional_header_ptr =
            unsafe { std::ptr::addr_of!((*self.get_nt_headers_ptr()).OptionalHeader) } as *const u8;

        // get the size of the optional header so we can add it to optional header addr.
        let optional_header_sz = self.get_nt_headers().FileHeader.SizeOfOptionalHeader as usize;

        // get a pointer to the section header.
        let section_header_ptr =
            unsafe { optional_header_ptr.add(optional_header_sz) as *mut IMAGE_SECTION_HEADER };

        // get the number of sections.
        let section_count = self.get_nt_headers().FileHeader.NumberOfSections;

        Ok(unsafe { std::slice::from_raw_parts_mut(section_header_ptr, section_count as usize) })
    }

    /// Return a poninter, that points to an address inside of a section specified by the RVA.
    pub fn get_pointer_from_section(&self, rva: u32) -> Result<*const u8> {
        for section in self.get_section_headers()? {
            let start_address = section.VirtualAddress;
            let end_address = section.VirtualAddress + section.SizeOfRawData;

            // if the rva is in the range of the section.
            if rva >= start_address && rva < end_address {
                // get offset of the target from the section.
                let delta = rva as usize - section.VirtualAddress as usize;

                unsafe {
                    return Ok(self
                        .bytes
                        .as_ptr()
                        .add(section.PointerToRawData as usize + delta));
                }
            }
        }

        Err(PeError::NotInSection)
    }

    /// Gets an RVA from a pointer to the raw data.
    pub fn get_rva_from_pointer(&self, ptr: u64) -> Result<u32> {
        // get the offset into the file.
        let raw_offset = (ptr - self.bytes.as_ptr() as u64) as u32;

        // make sure the offset is within boundaries and not some random pointer.
        if raw_offset >= self.bytes.len() as u32 {
            return Err(PeError::NotInSection);
        }

        for section in self.get_section_headers()? {
            let start_address = section.PointerToRawData;
            let end_address = section.PointerToRawData + section.SizeOfRawData;

            // if the offset is in the range of the section.
            if raw_offset >= start_address && raw_offset < end_address {
                // get offset of the target from the section.
                let delta = raw_offset - section.PointerToRawData;

                return Ok(section.VirtualAddress + delta);
            }
        }

        Err(PeError::NotInSection)
    }

    pub fn set_import_directory_rva(&self, rva: u32) {
        let optional_header_ptr =
            unsafe { std::ptr::addr_of!((*self.get_nt_headers_ptr()).OptionalHeader) }
                as *mut IMAGE_OPTIONAL_HEADER64;

        unsafe {
            (*optional_header_ptr).DataDirectory[IMAGE_DIRECTORY_ENTRY::IMPORT].VirtualAddress =
                rva;
        }
    }

    /// This will parse the import directory for import descriptors, and return them.
    pub fn get_import_descriptors(&self) -> Result<&mut [IMAGE_IMPORT_DESCRIPTOR]> {
        // get the import data directory.
        let import_directory =
            self.get_nt_headers().OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY::IMPORT];

        if import_directory.VirtualAddress == 0 {
            todo!("make it so that we create our own directory.");
        }

        // get a pointer to the image import descriptor.
        let pointer = self.get_pointer_from_section(import_directory.VirtualAddress)?
            as *mut IMAGE_IMPORT_DESCRIPTOR;

        Ok(unsafe {
            std::slice::from_raw_parts_mut(
                pointer,
                import_directory.Size as usize / std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>() - 1,
            )
        })
    }

    /// Given a descriptor, return a vector of all of its ILT 'Thunks'.
    pub fn get_ilt_thunks(
        &self,
        descriptor: &IMAGE_IMPORT_DESCRIPTOR,
    ) -> Result<Vec<IMAGE_THUNK_DATA64>> {
        let mut thunk_ptr = unsafe {
            self.get_pointer_from_section(descriptor.Anonymous.OriginalFirstThunk)?
                as *const IMAGE_THUNK_DATA64
        };

        let mut thunks: Vec<_> = Vec::new();

        loop {
            // deref thunk so we can read its data.
            let thunk = unsafe { thunk_ptr.read_unaligned() };

            // ensure that the current thunk is valid.
            if unsafe { thunk.u1.AddressOfData } == 0 {
                break;
            }

            thunks.push(thunk);

            unsafe {
                // advance the pointer to the next thunk.
                thunk_ptr = thunk_ptr.add(1);
            }
        }

        Ok(thunks)
    }

    pub fn get_thunk_function_name(&self, thunk: &IMAGE_THUNK_DATA64) -> Result<String> {
        // this will actually fail if it's an ordinal, pretty cool.
        let pointer = self.get_pointer_from_section(unsafe { thunk.u1.AddressOfData as _ })?
            as *const IMAGE_IMPORT_BY_NAME;

        // a pointer to the name part of the struct.
        // this struct uses the 1 element array C idiom thing.
        let name_ptr = unsafe { &(*pointer).Name as *const i8 };

        // get the length of the string.
        let length = (0..)
            .take_while(|&i| unsafe { *name_ptr.add(i) } != 0)
            .count();

        let name_slice = unsafe { std::slice::from_raw_parts(name_ptr as *const u8, length) };

        Ok(String::from_utf8_lossy(name_slice).to_string())
    }

    /// Given an RVA, return a string from its location.
    pub fn get_string_at_rva(&self, rva: u32) -> Result<String> {
        // get a pointer to the string.
        let string_pointer = self.get_pointer_from_section(rva)?;

        let length = unsafe {
            // find the null byte from the start of the pointer.
            std::slice::from_raw_parts(string_pointer, isize::MAX as usize)
                .iter()
                .position(|&byte| byte == 0)
                .unwrap_or(0)
        };

        // NOTE: for some reason using string from raw parts crashes it.
        let slice = unsafe { std::slice::from_raw_parts(string_pointer, length) };

        Ok(String::from_utf8_lossy(slice).to_string())
    }

    pub fn get_size_of_headers(&self) -> u32 {
        // instea of getting the size of the DOS header, we start from the nt header, so that it
        // includes the DOS stub B).
        self.get_dos_header().e_lfanew as u32
            + std::mem::size_of::<IMAGE_NT_HEADERS64>() as u32
            + (self.get_nt_headers().FileHeader.NumberOfSections as u32
                * std::mem::size_of::<IMAGE_SECTION_HEADER>() as u32)
    }

    pub fn get_size_of_initialized_data(&self) -> Result<u32> {
        Ok(self
            .get_section_headers()?
            .iter()
            // TODO: use the section permission enum.
            .filter(|s| (s.Characteristics & 0x40) != 0)
            .map(|s| s.SizeOfRawData)
            .sum::<u32>())
    }

    pub fn add_new_import_section(
        &mut self,
        name: Option<&str>,
        size: u32,
    ) -> Result<IMAGE_SECTION_HEADER> {
        // create a new section header that we'll append to the table.
        let mut section = IMAGE_SECTION_HEADER::default();

        // set the section name if specified.
        if let Some(name) = name {
            section.set_name(name);
        }

        let file_alignment = self.get_nt_headers().OptionalHeader.FileAlignment;
        let section_alignment = self.get_nt_headers().OptionalHeader.SectionAlignment;

        // get the last section in the section headers.
        let last_section = self
            .get_section_headers()?
            .into_iter()
            .last()
            .ok_or(PeError::NoSection)?;

        // For executable images, this must be a multiple of FileAlignment from the optional header. - MSDN.
        section.PointerToRawData =
            (last_section.PointerToRawData + last_section.SizeOfRawData).align(file_alignment);

        // in the docs, it doesn't say that this needs to be aligned.
        // yet in practice, it does need to be aligned, so... thanks microsoft.
        section.VirtualAddress = (last_section.VirtualAddress
            + unsafe { last_section.Misc.VirtualSize })
        .align(section_alignment);

        // make sure the size is properly aligned.
        section.SizeOfRawData = size.align(file_alignment);

        // make sure the size is properly aligned.
        section.Misc.VirtualSize = size.align(section_alignment);

        // IMAGE_SCN_CNT_INITIALIZED_DATA (0x00000040)
        // IMAGE_SCN_MEM_READ             (0x40000000)
        section.Characteristics = 0x40000040;

        // pointer to new section header.
        let new_section_ptr = unsafe { (last_section as *mut IMAGE_SECTION_HEADER).add(1) };

        unsafe { *new_section_ptr = section }

        // get a mutable pointer to the file header.
        let file_header_ptr: *mut IMAGE_FILE_HEADER =
            unsafe { std::ptr::addr_of!((*self.get_nt_headers_ptr()).FileHeader) as *mut _ };

        // increase the number of sections.
        unsafe { (*file_header_ptr).NumberOfSections += 1 }

        self.bytes
            .resize(self.bytes.len() + section.SizeOfRawData as usize, 0);

        unsafe {
            // correct the size of headers.
            (*(self.get_nt_headers_ptr() as *mut IMAGE_NT_HEADERS64))
                .OptionalHeader
                .SizeOfHeaders = self.get_size_of_headers();
        }

        unsafe {
            // correct the size of image.
            (*(self.get_nt_headers_ptr() as *mut IMAGE_NT_HEADERS64))
                .OptionalHeader
                .SizeOfImage = section.VirtualAddress + section.Misc.VirtualSize;
        }

        unsafe {
            // correct the size of intialized data.
            (*(self.get_nt_headers_ptr() as *mut IMAGE_NT_HEADERS64))
                .OptionalHeader
                .SizeOfInitializedData = self.get_size_of_initialized_data()?;
        }

        Ok(section)
    }

    /// Copy old import directory to new area.
    pub fn copy_imports_to_rva(&self, rva: u32) -> Result<()> {
        let import_directory =
            self.get_nt_headers().OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY::IMPORT];

        // get the pointer to the target import descriptors.
        let import_descriptors = self.get_pointer_from_section(import_directory.VirtualAddress)?
            as *mut IMAGE_IMPORT_DESCRIPTOR;

        let new_ptr = self.get_pointer_from_section(rva)? as *mut IMAGE_IMPORT_DESCRIPTOR;

        unsafe {
            std::ptr::copy_nonoverlapping(
                import_descriptors,
                new_ptr,
                import_directory.Size as usize / std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>() - 1,
            );
        }

        Ok(())
    }

    /// This will append imports to the import descriptors.
    ///
    /// This will only work one time per import directory.
    /// This also assumes the start of the section is where directory is.
    pub fn add_imports_for_section(
        &mut self,
        section_name: Option<&str>,
        imports: Vec<Import>,
    ) -> Result<()> {
        // either get the section from name, or get the last section.
        let section = if let Some(name) = section_name {
            self.get_section_headers()?
                .iter()
                .find(|s| s.get_name() == name)
                .ok_or(PeError::NoSection)?
        } else {
            self.get_section_headers()?
                .last()
                .ok_or(PeError::NoSection)?
        };

        let section_ptr = self.get_pointer_from_section(section.VirtualAddress)?;

        // get a pointer to the section after the descriptors.
        let mut dll_name_section_ptr = unsafe {
            section_ptr.add(
                (self.get_import_descriptors()?.len() + imports.len() + 1)
                    * std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>(),
            ) as *mut DLL_NAME
        };

        let thunk_section_ptr = unsafe { dll_name_section_ptr.add(imports.len()) as u64 };

        // NOTE: yes ik this is cursed, but it's easier to shadow this var, than to refactor a bit.
        // it's very annoying, but I need to align this so that I can recast it in the future.
        let mut thunk_section_ptr = thunk_section_ptr
            .align(std::mem::size_of::<IMAGE_THUNK_DATA64>() as u64)
            as *mut IMAGE_THUNK_DATA64;

        // get the total functions from every dll specified, plus null thunk.
        let total_functions = imports.iter().map(|i| i.functions.len() + 1).sum();

        let function_names = unsafe {
            std::slice::from_raw_parts_mut(
                thunk_section_ptr.add(total_functions) as *mut IMAGE_IMPORT_BY_NAME_EXTENDED,
                total_functions,
            )
        };

        // used to keep track of which `function_names` element we're on.
        let mut current_function_name = 0;

        let ptr = self
            .get_import_descriptors()?
            .into_iter()
            .last()
            .ok_or(PeError::NoDescriptor)? as *mut IMAGE_IMPORT_DESCRIPTOR;

        // a pointer to the start of our image descriptors.
        let descriptors = unsafe { std::slice::from_raw_parts_mut(ptr.add(1), imports.len()) };

        unsafe {
            for (i, descriptor) in descriptors.into_iter().enumerate() {
                // set to default descriptor value, otherwise uninit.
                *descriptor = IMAGE_IMPORT_DESCRIPTOR::default();

                // set the name of the dll then place it after the descriptor entries.
                let mut name = DLL_NAME::default();
                name.set_dll_name(&imports[i].file);

                // set the dll name then increment name section pointer for next iteration.
                *dll_name_section_ptr = name;

                // set the descriptor name to the rva of the dll name struct.
                descriptor.Name = self.get_rva_from_pointer(dll_name_section_ptr as u64)?;

                dll_name_section_ptr = dll_name_section_ptr.add(1);

                // for our current descriptor, create a slice of thunks for it.
                let thunks = std::slice::from_raw_parts_mut(
                    thunk_section_ptr,
                    imports[i].functions.len() + 1,
                );

                // get the length of the thunks.
                let thunks_len = thunks.len();

                for (n, thunk) in thunks.into_iter().enumerate() {
                    *thunk = IMAGE_THUNK_DATA64::default();

                    // if it's the final thunk, then break after setting it to an empty struct.
                    if n == thunks_len - 1 {
                        break;
                    }

                    // this will be the thunks 'address-of-data', aka function from import.
                    function_names[current_function_name] =
                        IMAGE_IMPORT_BY_NAME_EXTENDED::default();

                    function_names[current_function_name].set_name(&imports[i].functions[n]);

                    // set the name of the function to the address of the `function_name` member.
                    thunk.u1.AddressOfData = self.get_rva_from_pointer(
                        &mut function_names[current_function_name]
                            as *mut IMAGE_IMPORT_BY_NAME_EXTENDED as u64,
                    )? as u64;

                    current_function_name += 1;
                }

                let thunk_rva =
                    self.get_rva_from_pointer(thunks.first().unwrap() as *const _ as u64)?;

                // set the ILT thunk to this thunk.
                descriptor.Anonymous.OriginalFirstThunk = thunk_rva;

                thunk_section_ptr = thunk_section_ptr.add(thunks_len);
            }
        }

        Ok(())
    }

    /// Get the size of current and new import descriptors.
    /// NOTE: this assumes that this is called in the context of newly added import sections.
    pub fn get_custom_import_size(&self, imports: &Vec<Import>) -> Result<usize> {
        let old_import_descriptor_size =
            self.get_import_descriptors()?.len() * std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();

        let new_import_descriptor_size =
            imports.len() * std::mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>();

        // size of the section after import descriptors.
        let dll_names_size = imports.len() * std::mem::size_of::<DLL_NAME>();

        // the total amount of thunks that will get created.
        let total_functions: usize = imports.iter().map(|i| i.functions.len() + 1).sum();

        let thunks_size = total_functions * std::mem::size_of::<IMAGE_THUNK_DATA64>();

        // one function name for every thunk.
        let function_names_size =
            total_functions * std::mem::size_of::<IMAGE_IMPORT_BY_NAME_EXTENDED>();

        Ok(old_import_descriptor_size
            + new_import_descriptor_size
            + dll_names_size
            + total_functions
            + thunks_size
            + function_names_size
            + 16)
    }

    /// Exports the `bytes` buffer containing the *potentially* modified PE file.
    pub fn export(&self, name: &str) -> Result<()> {
        // create the new file.
        let mut file = std::fs::File::create(name)?;

        // write our modified pe file to disk.
        file.write_all(&self.bytes)?;

        Ok(())
    }
}
