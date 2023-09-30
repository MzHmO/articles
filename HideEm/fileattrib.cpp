#include <iostream>
#include <windows.h>
#include <locale.h>
int main()
{
    setlocale(LC_ALL, "");
    const char* fileName = "C:\\Users\\Admin\\Downloads\\1.txt";
    DWORD attributes = GetFileAttributesA(fileName);

    if (attributes != INVALID_FILE_ATTRIBUTES)
    {
        // Добавляем атрибут "Скрытый"
        attributes |= FILE_ATTRIBUTE_HIDDEN;

        // Добавляем атрибут "Системный"
        attributes |= FILE_ATTRIBUTE_SYSTEM;

        if (SetFileAttributesA(fileName, attributes))
        {
            std::cout << "Атрибуты успешно изменены." << std::endl;
        }
        else
        {
            std::cout << "Не удалось изменить атрибуты файла." << std::endl;
        }
    }
    else
    {
        std::cout << "Не удалось получить атрибуты файла." << std::endl;
    }

    return 0;
}